class ContextBuilder:

    @staticmethod
    def build(
        retrieved_chunks,
        alert=None
    ):
        context_parts = []

        # RAG knowledge
        context_parts.append(
            "=== SECURITY KNOWLEDGE ==="
        )

        for index, chunk in enumerate(
            retrieved_chunks,
            start=1
        ):
            context_parts.append(
                f"\n--- Knowledge {index} ---"
            )
            context_parts.append(
                f"Source: {chunk['source']}"
            )
            context_parts.append(
                f"Similarity: {chunk['score']:.4f}"
            )
            context_parts.append(
                chunk["text"]
            )

        # Live alert evidence
        context_parts.append(
            "\n=== LIVE WAZUH ALERT ==="
        )

        if alert:
            context_parts.append(
                f"Alert ID: {alert.get('alert_id')}"
            )
            context_parts.append(
                f"Rule ID: {alert.get('rule_id')}"
            )
            context_parts.append(
                f"Rule Level: {alert.get('rule_level')}"
            )
            context_parts.append(
                f"Description: {alert.get('rule_description')}"
            )
            context_parts.append(
                f"Source IP: {alert.get('source_ip')}"
            )
            context_parts.append(
                f"Username: {alert.get('source_user')}"
            )
            context_parts.append(
                f"Destination IP: {alert.get('destination_ip')}"
            )
            context_parts.append(
                f"Destination Port: {alert.get('destination_port')}"
            )
            context_parts.append(
                f"Full Log: {alert.get('full_log')}"
            )

        return "\n".join(context_parts)


if __name__ == "__main__":

    sample_chunks = [
        {
            "source": "soc_knowledge.md",
            "chunk_id": 0,
            "score": 0.5361,
            "text": (
                "Brute force authentication involves "
                "repeated failed authentication attempts."
            )
        }
    ]

    sample_alert = {
        "alert_id": "12345",
        "rule_id": "5710",
        "rule_level": 5,
        "rule_description": (
            "sshd: Attempt to login using "
            "a non-existent user"
        ),
        "source_ip": "192.168.1.200",
        "source_user": "admin",
        "destination_ip": None,
        "destination_port": 22,
        "full_log": (
            "Failed password for invalid user admin "
            "from 192.168.1.200 port 22 ssh2"
        )
    }

    context = ContextBuilder.build(
        sample_chunks,
        sample_alert
    )

    print("===== CONTEXT BUILDER TEST =====")
    print(context)
    print("\nContext builder test: PASSED")
