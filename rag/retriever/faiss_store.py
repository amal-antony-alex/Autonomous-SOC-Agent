from pathlib import Path

import faiss
import numpy as np

from rag.document_loader import document_loader
from rag.embeddings.embedder import embedder


class FAISSStore:

    def __init__(
        self,
        index_path="rag/embeddings/faiss.index",
        metadata_path="rag/embeddings/metadata.npy"
    ):
        self.index_path = Path(index_path)
        self.metadata_path = Path(metadata_path)

        self.index = None
        self.metadata = []

    def build(self):

        chunks = document_loader.load_and_chunk()

        texts = [
            chunk["text"]
            for chunk in chunks
        ]

        vectors = embedder.embed(texts)

        vectors = np.asarray(
            vectors,
            dtype="float32"
        )

        dimension = vectors.shape[1]

        self.index = faiss.IndexFlatIP(dimension)

        self.index.add(vectors)

        self.metadata = chunks

        faiss.write_index(
            self.index,
            str(self.index_path)
        )

        np.save(
            self.metadata_path,
            np.array(
                self.metadata,
                dtype=object
            ),
            allow_pickle=True
        )

        return {
            "chunks": len(chunks),
            "dimension": dimension
        }

    def load(self):

        self.index = faiss.read_index(
            str(self.index_path)
        )

        self.metadata = np.load(
            self.metadata_path,
            allow_pickle=True
        ).tolist()

    def search(
        self,
        query,
        top_k=3
    ):

        query_vector = embedder.embed(
            [query]
        )

        query_vector = np.asarray(
            query_vector,
            dtype="float32"
        )

        scores, indices = self.index.search(
            query_vector,
            top_k
        )

        results = []

        for score, index in zip(
            scores[0],
            indices[0]
        ):

            if index == -1:
                continue

            results.append(
                {
                    "score": float(score),
                    "source": self.metadata[index]["source"],
                    "chunk_id": self.metadata[index]["chunk_id"],
                    "text": self.metadata[index]["text"]
                }
            )

        return results


if __name__ == "__main__":

    store = FAISSStore()

    result = store.build()

    print("===== FAISS BUILD TEST =====")
    print(f"Chunks indexed: {result['chunks']}")
    print(f"Embedding dimension: {result['dimension']}")

    store.load()

    results = store.search(
        "multiple failed SSH login attempts",
        top_k=3
    )

    print("\n===== SEARCH TEST =====")

    for result in results:
        print(
            f"\nScore: {result['score']:.4f}"
        )
        print(
            f"Source: {result['source']}"
        )
        print(
            f"Chunk ID: {result['chunk_id']}"
        )
        print(
            result["text"][:300]
        )

    print("\nFAISS test: PASSED")
