#pragma once

#include <atomic>
#include <chrono>
#include <functional>
#include <future>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>
#include <string>
#include <thread>
#include <vector>
#include <nlohmann/json.hpp>

namespace orpheus::core {

/**
 * Cancellation token for long-running operations
 */
class CancellationToken {
public:
    CancellationToken() : cancelled_(false) {}

    void Cancel() { cancelled_.store(true); }
    bool IsCancelled() const { return cancelled_.load(); }

private:
    std::atomic<bool> cancelled_;
};

using CancellationTokenPtr = std::shared_ptr<CancellationToken>;

/**
 * Progress callback signature
 * @param progress Value between 0.0 and 1.0
 * @param message Optional status message
 */
using ProgressCallback = std::function<void(float progress, const std::string& message)>;

/**
 * Task function signature - receives cancellation token and progress callback
 * Returns JSON result on success, throws on error
 */
using TaskFunction = std::function<nlohmann::json(CancellationTokenPtr, ProgressCallback)>;

/**
 * Task state
 */
enum class TaskState {
    Pending,    // Queued but not started
    Running,    // Currently executing
    Completed,  // Finished successfully
    Failed,     // Finished with error
    Cancelled   // Cancelled by user
};

inline std::string TaskStateToString(TaskState state) {
    switch (state) {
        case TaskState::Pending: return "pending";
        case TaskState::Running: return "running";
        case TaskState::Completed: return "completed";
        case TaskState::Failed: return "failed";
        case TaskState::Cancelled: return "cancelled";
    }
    return "unknown";
}

/**
 * Information about a task
 */
struct TaskInfo {
    std::string id;
    std::string type;           // e.g., "pattern_scan", "rtti_scan"
    std::string description;    // Human-readable description
    TaskState state = TaskState::Pending;
    float progress = 0.0f;      // 0.0 to 1.0
    std::string status_message;

    std::chrono::steady_clock::time_point created_at;
    std::chrono::steady_clock::time_point started_at;
    std::chrono::steady_clock::time_point completed_at;

    std::optional<nlohmann::json> result;
    std::optional<std::string> error;

    // Convert to JSON for MCP response
    nlohmann::json ToJson() const;
};

/**
 * Internal task structure with execution state
 */
struct Task {
    TaskInfo info;
    TaskFunction function;
    CancellationTokenPtr cancel_token;
    std::future<void> future;
};

/**
 * TaskManager - manages background tasks with progress tracking and cancellation
 *
 * Usage:
 *   auto& tm = TaskManager::Instance();
 *   std::string task_id = tm.StartTask("pattern_scan", "Scanning for pattern...",
 *       [](CancellationTokenPtr cancel, ProgressCallback progress) -> nlohmann::json {
 *           for (int i = 0; i < 100; i++) {
 *               if (cancel->IsCancelled()) throw std::runtime_error("Cancelled");
 *               progress(i / 100.0f, "Processing...");
 *               // do work
 *           }
 *           return {{"matches", results}};
 *       });
 *
 *   auto status = tm.GetTask(task_id);
 *   tm.CancelTask(task_id);
 */
class TaskManager {
public:
    static TaskManager& Instance();

    // Non-copyable, non-movable
    TaskManager(const TaskManager&) = delete;
    TaskManager& operator=(const TaskManager&) = delete;

    /**
     * Start a new background task
     * @param type Task type identifier (e.g., "pattern_scan")
     * @param description Human-readable description
     * @param function Task function to execute
     * @return Unique task ID
     */
    std::string StartTask(const std::string& type,
                          const std::string& description,
                          TaskFunction function);

    /**
     * Get task info by ID
     * @return TaskInfo if found, nullopt otherwise
     */
    std::optional<TaskInfo> GetTask(const std::string& id);

    /**
     * Cancel a running task
     * @return true if task was found and cancellation requested
     */
    bool CancelTask(const std::string& id);

    /**
     * List all tasks (optionally filtered by state)
     */
    std::vector<TaskInfo> ListTasks(std::optional<TaskState> state_filter = std::nullopt);

    /**
     * Remove completed/failed/cancelled tasks older than max_age
     */
    void CleanupTasks(std::chrono::seconds max_age = std::chrono::seconds(300));

    /**
     * Get count of tasks by state
     */
    struct TaskCounts {
        size_t pending = 0;
        size_t running = 0;
        size_t completed = 0;
        size_t failed = 0;
        size_t cancelled = 0;
        size_t total = 0;
    };
    TaskCounts GetTaskCounts();

private:
    TaskManager();
    ~TaskManager();

    std::string GenerateTaskId();
    void ExecuteTask(std::shared_ptr<Task> task);

    std::map<std::string, std::shared_ptr<Task>> tasks_;
    mutable std::mutex mutex_;

    std::atomic<uint64_t> task_counter_{0};
};

} // namespace orpheus::core
