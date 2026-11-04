"""
Leader orchestrator that spawns and manages subordinate bot workers.
This is an example controller for fold orchestrators and Micronauts.
"""

from __future__ import annotations

import json
import logging
import queue
import subprocess
import sys
import threading
import time
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("Orchestrator")


class TaskStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    STOPPED = "stopped"


@dataclass
class BotTask:
    id: str
    task_type: str
    parameters: Dict[str, Any]
    created_at: float
    status: TaskStatus = TaskStatus.PENDING
    result: Any = None
    error: Optional[str] = None
    worker_pid: Optional[int] = None


class BotOrchestrator:
    def __init__(self, max_workers: int = 3) -> None:
        self.max_workers = max_workers
        self.tasks: Dict[str, BotTask] = {}
        self.active_workers: Dict[int, subprocess.Popen[str]] = {}
        self.task_queue: "queue.Queue[str]" = queue.Queue()
        self.is_running = True

        self.monitor_thread = threading.Thread(target=self._monitor_workers, daemon=True)
        self.monitor_thread.start()

        self.processor_thread = threading.Thread(target=self._process_tasks, daemon=True)
        self.processor_thread.start()

        logger.info("Orchestrator initialized with %s max workers", max_workers)

    def create_task(self, task_type: str, parameters: Dict[str, Any]) -> str:
        """Create a new task and add it to the queue."""
        task_id = f"task_{int(time.time())}_{len(self.tasks)}"
        task = BotTask(
            id=task_id,
            task_type=task_type,
            parameters=parameters,
            created_at=time.time(),
        )

        self.tasks[task_id] = task
        self.task_queue.put(task_id)
        logger.info("Created task %s of type %s", task_id, task_type)
        return task_id

    def _process_tasks(self) -> None:
        """Process tasks from the queue and spawn workers."""
        while self.is_running:
            try:
                if len(self.active_workers) >= self.max_workers:
                    time.sleep(0.1)
                    continue

                task_id = self.task_queue.get(timeout=0.5)
                task = self.tasks[task_id]

                task.status = TaskStatus.RUNNING

                worker_script = self._get_worker_script(task.task_type)
                if worker_script:
                    self._spawn_worker(task, worker_script)
                else:
                    task.status = TaskStatus.FAILED
                    task.error = f"Unknown task type: {task.task_type}"
                    logger.error("Unknown task type: %s", task.task_type)

            except queue.Empty:
                continue
            except Exception as exc:
                logger.error("Error processing tasks: %s", exc)

    def _get_worker_script(self, task_type: str) -> Optional[str]:
        """Get the appropriate worker script for the task type."""
        scripts = {
            "data_processor": "data_worker_bot.py",
            "web_scraper": str(Path(__file__).resolve().parent.parent / "scraper_worker_bot.py"),
            "file_processor": "file_worker_bot.py",
            "monitor": "monitor_worker_bot.py",
            "calculator": "calculator_worker_bot.py",
        }
        return scripts.get(task_type)

    def _spawn_worker(self, task: BotTask, worker_script: str) -> None:
        """Spawn a worker bot in a separate process."""
        try:
            task_data = {
                "task_id": task.id,
                "task_type": task.task_type,
                "parameters": task.parameters,
            }

            task_json = json.dumps(task_data)

            process = subprocess.Popen(
                [sys.executable, worker_script],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )

            if process.stdin is None:
                raise RuntimeError("Worker stdin was not created")

            process.stdin.write(task_json + "\n")
            process.stdin.flush()

            self.active_workers[process.pid] = process
            task.worker_pid = process.pid

            logger.info("Spawned worker PID %s for task %s", process.pid, task.id)

            output_thread = threading.Thread(
                target=self._capture_worker_output,
                args=(process, task.id),
                daemon=True,
            )
            output_thread.start()

        except Exception as exc:
            task.status = TaskStatus.FAILED
            task.error = str(exc)
            logger.error("Failed to spawn worker for task %s: %s", task.id, exc)

    def _capture_worker_output(self, process: subprocess.Popen[str], task_id: str) -> None:
        """Capture output from a worker process."""
        try:
            stdout_data = ""
            if process.stdout is None:
                raise RuntimeError("Worker stdout was not created")

            for line in iter(process.stdout.readline, ""):
                if not line:
                    break
                stdout_data += line

                if "RESULT:" in line:
                    result_json = line.split("RESULT:", 1)[1].strip()
                    self._handle_worker_result(task_id, result_json)
                if "ERROR:" in line:
                    error_json = line.split("ERROR:", 1)[1].strip()
                    self._handle_worker_error(task_id, error_json)

            stderr_data = ""
            if process.stderr is not None:
                stderr_data = process.stderr.read()

            return_code = process.wait()

            if process.pid in self.active_workers:
                del self.active_workers[process.pid]

            if return_code == 0:
                logger.info("Worker for task %s completed successfully", task_id)
            else:
                task = self.tasks.get(task_id)
                if task and task.status == TaskStatus.RUNNING:
                    task.status = TaskStatus.FAILED
                    task.error = stderr_data or f"Process exited with code {return_code}"
                    logger.error("Worker for task %s failed: %s", task_id, stderr_data)

        except Exception as exc:
            logger.error("Error capturing output for task %s: %s", task_id, exc)

    def _handle_worker_result(self, task_id: str, result_json: str) -> None:
        """Handle result from worker."""
        try:
            result_data = json.loads(result_json)
            task = self.tasks.get(task_id)

            if task:
                task.status = TaskStatus.COMPLETED
                task.result = result_data.get("result")
                logger.info("Task %s completed with result: %s", task_id, task.result)

        except json.JSONDecodeError:
            logger.error("Invalid JSON result from task %s", task_id)
        except Exception as exc:
            logger.error("Error handling result for task %s: %s", task_id, exc)

    def _handle_worker_error(self, task_id: str, error_json: str) -> None:
        """Handle error payloads emitted by workers."""
        try:
            error_data = json.loads(error_json)
            task = self.tasks.get(task_id)
            if task:
                task.status = TaskStatus.FAILED
                task.error = error_data.get("error", "Unknown worker error")
                logger.error("Task %s failed with error: %s", task_id, task.error)
        except json.JSONDecodeError:
            logger.error("Invalid JSON error from task %s", task_id)

    def _monitor_workers(self) -> None:
        """Monitor worker processes."""
        while self.is_running:
            time.sleep(1)
            for pid, process in list(self.active_workers.items()):
                if process.poll() is not None and process.pid in self.active_workers:
                    del self.active_workers[pid]

    def get_task_status(self, task_id: str) -> Dict[str, Any]:
        """Get status of a specific task."""
        task = self.tasks.get(task_id)
        if task:
            return asdict(task)
        return {"error": "Task not found"}

    def list_tasks(self) -> List[Dict[str, Any]]:
        """List all tasks."""
        return [asdict(task) for task in self.tasks.values()]

    def stop_task(self, task_id: str) -> bool:
        """Stop a running task."""
        task = self.tasks.get(task_id)
        if task and task.worker_pid:
            process = self.active_workers.get(task.worker_pid)
            if process is None or process.poll() is not None:
                return False
            try:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
                task.status = TaskStatus.STOPPED
                logger.info("Stopped task %s", task_id)
                return True
            except (OSError, subprocess.SubprocessError):
                logger.exception("Could not stop worker for task %s", task_id)
        return False

    def stop_all(self) -> None:
        """Stop all workers and shutdown orchestrator."""
        logger.info("Shutting down orchestrator...")
        self.is_running = False

        for task in self.tasks.values():
            if task.status == TaskStatus.PENDING:
                task.status = TaskStatus.STOPPED

        for process in list(self.active_workers.values()):
            if process.poll() is not None:
                continue
            try:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            except (OSError, subprocess.SubprocessError):
                logger.exception("Failed to terminate worker process %s", process.pid)

        self.processor_thread.join(timeout=2)
        self.monitor_thread.join(timeout=2)

        logger.info("Orchestrator shutdown complete")


def create_worker_bot(script_name: str, script_content: str) -> None:
    """Helper to create worker bot scripts."""
    with open(script_name, "w", encoding="utf-8") as file_handle:
        file_handle.write(script_content)


DATA_WORKER_SCRIPT = '''#!/usr/bin/env python3
import json
import sys
import time


def process_data(parameters):
    """Example data processing function."""
    data = parameters.get('data', [])
    operation = parameters.get('operation', 'sum')

    if operation == 'sum':
        result = sum(data)
    elif operation == 'average':
        result = sum(data) / len(data) if data else 0
    elif operation == 'max':
        result = max(data) if data else 0
    elif operation == 'min':
        result = min(data) if data else 0
    else:
        result = None

    return result


if __name__ == "__main__":
    try:
        task_json = sys.stdin.readline().strip()
        task = json.loads(task_json)

        print(f"Worker started for task {task['task_id']}", flush=True)

        time.sleep(2)

        result = process_data(task['parameters'])

        result_data = {
            'task_id': task['task_id'],
            'result': result,
            'status': 'completed'
        }

        print(f"RESULT:{json.dumps(result_data)}", flush=True)

    except Exception as exc:
        error_data = {
            'task_id': task.get('task_id', 'unknown'),
            'error': str(exc),
            'status': 'failed'
        }
        print(f"ERROR:{json.dumps(error_data)}", flush=True)
        sys.exit(1)
'''

FILE_WORKER_SCRIPT = '''#!/usr/bin/env python3
import hashlib
import json
import sys
import time


def process_file(parameters):
    """Example file processing."""
    operation = parameters.get('operation', 'hash')
    content = parameters.get('content', '')

    if operation == 'hash':
        result = hashlib.md5(content.encode()).hexdigest()
    elif operation == 'count':
        result = {
            'characters': len(content),
            'words': len(content.split()),
            'lines': len(content.split('\\n'))
        }
    elif operation == 'reverse':
        result = content[::-1]
    else:
        result = None

    return result


if __name__ == "__main__":
    try:
        task_json = sys.stdin.readline().strip()
        task = json.loads(task_json)

        print(f"File worker started for {task['task_id']}", flush=True)
        time.sleep(1)

        result = process_file(task['parameters'])

        result_data = {
            'task_id': task['task_id'],
            'result': result,
            'status': 'completed'
        }

        print(f"RESULT:{json.dumps(result_data)}", flush=True)

    except Exception as exc:
        error_data = {'error': str(exc)}
        print(f"ERROR:{json.dumps(error_data)}", flush=True)
        sys.exit(1)
'''

CALCULATOR_WORKER_SCRIPT = '''#!/usr/bin/env python3
import json
import sys
import time


def calculate(parameters):
    """Perform calculations."""
    operation = parameters.get('operation')
    a = parameters.get('a', 0)
    b = parameters.get('b', 0)

    operations = {
        'add': lambda x, y: x + y,
        'subtract': lambda x, y: x - y,
        'multiply': lambda x, y: x * y,
        'divide': lambda x, y: x / y if y != 0 else 'undefined',
        'power': lambda x, y: x ** y
    }

    if operation in operations:
        return operations[operation](a, b)
    return None


if __name__ == "__main__":
    try:
        task_json = sys.stdin.readline().strip()
        task = json.loads(task_json)

        print(f"Calculator worker started for {task['task_id']}", flush=True)
        time.sleep(0.5)

        result = calculate(task['parameters'])

        result_data = {
            'task_id': task['task_id'],
            'result': result,
            'status': 'completed'
        }

        print(f"RESULT:{json.dumps(result_data)}", flush=True)

    except Exception as exc:
        error_data = {'error': str(exc)}
        print(f"ERROR:{json.dumps(error_data)}", flush=True)
        sys.exit(1)
'''

MONITOR_WORKER_SCRIPT = '''#!/usr/bin/env python3
import json
import sys
import time


def capture_metrics(parameters):
    """Return a basic monitoring payload."""
    return {
        'service': parameters.get('service', 'unknown'),
        'status': parameters.get('status', 'ok'),
        'latency_ms': parameters.get('latency_ms', 0),
        'timestamp': time.time()
    }


if __name__ == "__main__":
    try:
        task_json = sys.stdin.readline().strip()
        task = json.loads(task_json)

        print(f"Monitor worker started for {task['task_id']}", flush=True)
        time.sleep(0.5)

        result = capture_metrics(task['parameters'])

        result_data = {
            'task_id': task['task_id'],
            'result': result,
            'status': 'completed'
        }

        print(f"RESULT:{json.dumps(result_data)}", flush=True)

    except Exception as exc:
        error_data = {'error': str(exc)}
        print(f"ERROR:{json.dumps(error_data)}", flush=True)
        sys.exit(1)
'''


def create_all_workers() -> None:
    """Create all worker bot scripts."""
    workers = {
        "data_worker_bot.py": DATA_WORKER_SCRIPT,
        "file_worker_bot.py": FILE_WORKER_SCRIPT,
        "calculator_worker_bot.py": CALCULATOR_WORKER_SCRIPT,
        "monitor_worker_bot.py": MONITOR_WORKER_SCRIPT,
    }

    for filename, content in workers.items():
        create_worker_bot(filename, content)
        print(f"Created {filename}")


def demo() -> None:
    """Demonstrate the bot orchestration system."""
    print("=" * 50)
    print("BOT ORCHESTRATION SYSTEM DEMO")
    print("=" * 50)

    create_all_workers()

    orchestrator = BotOrchestrator(max_workers=2)

    try:
        tasks = [
            ("data_processor", {"data": [1, 2, 3, 4, 5], "operation": "sum"}),
            ("calculator", {"operation": "multiply", "a": 10, "b": 20}),
            ("file_processor", {"content": "Hello World\nThis is a test", "operation": "count"}),
            ("web_scraper", {"url": "https://example.com", "query": "example domain"}),
            ("data_processor", {"data": [100, 200, 300], "operation": "average"}),
            ("monitor", {"service": "fold-orchestrator", "latency_ms": 4, "status": "ok"}),
        ]

        task_ids = []
        for task_type, params in tasks:
            task_id = orchestrator.create_task(task_type, params)
            task_ids.append(task_id)

        print(f"\nCreated {len(task_ids)} tasks")
        print("Waiting for tasks to complete...\n")

        completed_tasks = set()
        start_time = time.time()

        while len(completed_tasks) < len(task_ids) and time.time() - start_time < 30:
            time.sleep(1)

            for task_id in task_ids:
                if task_id not in completed_tasks:
                    status = orchestrator.get_task_status(task_id)
                    if status["status"] in ["completed", "failed", "stopped"]:
                        print(f"Task {task_id}: {status['status']}")
                        if status["status"] == "completed":
                            print(f"  Result: {status.get('result')}")
                        completed_tasks.add(task_id)

        print("\nFinal Task Status:")
        for task in orchestrator.list_tasks():
            print(f"{task['id']}: {task['status']} - Result: {task.get('result')}")

    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        orchestrator.stop_all()


if __name__ == "__main__":
    demo()
