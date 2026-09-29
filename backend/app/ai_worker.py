import traceback

from app.services.redis_queue import redis_queue
from app.services.rag_service import rag_service
from app.services.alert_correlator import alert_correlator


def process_alert(task):

    normalized_alert = task["normalized_alert"]
    rulebook_matches = task["rulebook_matches"]
    db_alert_id = task["db_alert_id"]

    # --------------------------------------------------
    # Alert Correlation
    # --------------------------------------------------

    print(
        "Starting alert correlation...",
        flush=True
    )

    correlation_result = alert_correlator.correlate(
        normalized_alert
    )

    print(
        "Alert correlation completed.",
        flush=True
    )

    print()
    print(
        "----- Alert Correlation -----",
        flush=True
    )

    print(
        f"Correlated: "
        f"{correlation_result.get('correlated')}",
        flush=True
    )

    print(
        f"Alert count: "
        f"{correlation_result.get('alert_count')}",
        flush=True
    )

    print(
        f"Source IP: "
        f"{correlation_result.get('source_ip')}",
        flush=True
    )

    print(
        "Correlation output processed.",
        flush=True
    )

    # --------------------------------------------------
    # Investigation
    # --------------------------------------------------

    print()
    print(
        "==================================================",
        flush=True
    )

    print(
        "AI INVESTIGATION STARTED",
        flush=True
    )

    print(
        "==================================================",
        flush=True
    )

    print(
        f"Database Alert ID: "
        f"{db_alert_id}",
        flush=True
    )

    print(
        f"Alert ID: "
        f"{normalized_alert.get('alert_id')}",
        flush=True
    )

    print(
        f"Rule ID: "
        f"{normalized_alert.get('rule_id')}",
        flush=True
    )

    try:

        # --------------------------------------------------
        # RAG Investigation
        # --------------------------------------------------

        print(
            "Starting RAG investigation...",
            flush=True
        )

        result = rag_service.investigate(
            normalized_alert,
            rulebook_matches=rulebook_matches,
            correlation_result=correlation_result
        )

        print(
            "RAG investigation completed.",
            flush=True
        )

        # --------------------------------------------------
        # Tiny CyberLLM
        # --------------------------------------------------

        print()
        print(
            "----- Tiny CyberLLM -----",
            flush=True
        )

        print(
            result["tiny_cyberllm"]["analysis"],
            flush=True
        )

        # --------------------------------------------------
        # Qwen Verification
        # --------------------------------------------------

        print()
        print(
            "----- Qwen Verification -----",
            flush=True
        )

        print(
            result["qwen_verification"]["analysis"],
            flush=True
        )

        # --------------------------------------------------
        # Evidence Validation
        # --------------------------------------------------

        print()
        print(
            "----- Evidence Validation -----",
            flush=True
        )

        print(
            result["evidence_validation"],
            flush=True
        )

        # --------------------------------------------------
        # Investigation Complete
        # --------------------------------------------------

        print()
        print(
            "==================================================",
            flush=True
        )

        print(
            "AI INVESTIGATION COMPLETED",
            flush=True
        )

        print(
            "==================================================",
            flush=True
        )

        print()

    except Exception as error:

        print()
        print(
            "==================================================",
            flush=True
        )

        print(
            "AI INVESTIGATION FAILED",
            flush=True
        )

        print(
            "==================================================",
            flush=True
        )

        print(
            f"Error type: "
            f"{type(error).__name__}",
            flush=True
        )

        print(
            f"Error: "
            f"{error}",
            flush=True
        )

        traceback.print_exc()

        print(
            "==================================================",
            flush=True
        )

        print()


def main():

    print(
        "Redis AI investigation worker started.",
        flush=True
    )

    print(
        f"Redis queue: "
        f"{redis_queue.queue_name}",
        flush=True
    )

    while True:

        task = redis_queue.dequeue(
            timeout=5
        )

        if task is None:
            continue

        print(
            "Task received from Redis.",
            flush=True
        )

        print(
            f"Remaining queue size: "
            f"{redis_queue.size()}",
            flush=True
        )

        process_alert(task)


if __name__ == "__main__":
    main()

