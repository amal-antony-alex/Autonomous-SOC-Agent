from rag.retriever.faiss_store import FAISSStore
from rag.retriever.context_builder import ContextBuilder


class RAGPipeline:

    def __init__(self):
        self.store = FAISSStore()

        self.store.load()

    def build_context(
        self,
        query,
        alert=None,
        top_k=3
    ):
        retrieved_chunks = self.store.search(
            query=query,
            top_k=top_k
        )

        context = ContextBuilder.build(
            retrieved_chunks=retrieved_chunks,
            alert=alert
        )

        return {
            "query": query,
            "retrieved_chunks": retrieved_chunks,
            "context": context
        }


if __name__ == "__main__":

    pipeline = RAGPipeline()

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

    result = pipeline.build_context(
        query="multiple failed SSH login attempts",
        alert=sample_alert,
        top_k=3
    )

    print("===== RAG PIPELINE TEST =====")

    print("\nQuery:")
    print(result["query"])

    print("\nRetrieved Chunks:")

    for chunk in result["retrieved_chunks"]:
        print(
            f"- Chunk {chunk['chunk_id']} "
            f"(score={chunk['score']:.4f})"
        )

    print("\n===== FINAL CONTEXT =====")
    print(result["context"])

    print("\nRAG pipeline test: PASSED")
