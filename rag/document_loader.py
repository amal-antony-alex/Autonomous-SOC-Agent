from pathlib import Path


class DocumentLoader:

    def __init__(self, documents_dir="rag/documents"):
        self.documents_dir = Path(documents_dir)

    def load_documents(self):
        documents = []

        for file_path in sorted(self.documents_dir.glob("*.md")):
            text = file_path.read_text(
                encoding="utf-8"
            )

            documents.append(
                {
                    "source": file_path.name,
                    "text": text,
                }
            )

        return documents

    @staticmethod
    def chunk_text(
        text,
        chunk_size=800,
        chunk_overlap=100
    ):
        chunks = []

        start = 0
        text_length = len(text)

        while start < text_length:
            end = start + chunk_size

            chunk = text[start:end].strip()

            if chunk:
                chunks.append(chunk)

            if end >= text_length:
                break

            start = end - chunk_overlap

        return chunks

    def load_and_chunk(self):
        documents = []
        document_list = self.load_documents()

        for document in document_list:
            chunks = self.chunk_text(
                document["text"]
            )

            for index, chunk in enumerate(chunks):
                documents.append(
                    {
                        "source": document["source"],
                        "chunk_id": index,
                        "text": chunk,
                    }
                )

        return documents


document_loader = DocumentLoader()


if __name__ == "__main__":

    chunks = document_loader.load_and_chunk()

    print("===== RAG DOCUMENT LOADER TEST =====")
    print(f"Documents: {len(document_loader.load_documents())}")
    print(f"Chunks: {len(chunks)}")

    for chunk in chunks[:3]:
        print("\n--- Chunk ---")
        print(f"Source: {chunk['source']}")
        print(f"Chunk ID: {chunk['chunk_id']}")
        print(chunk["text"][:300])
