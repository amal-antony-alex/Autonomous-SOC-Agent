from sentence_transformers import SentenceTransformer


class SecurityEmbedder:

    def __init__(
        self,
        model_name="all-MiniLM-L6-v2"
    ):
        self.model = SentenceTransformer(model_name)

    def embed(self, texts):
        return self.model.encode(
            texts,
            convert_to_numpy=True,
            normalize_embeddings=True
        )


embedder = SecurityEmbedder()


if __name__ == "__main__":

    sample_texts = [
        "Brute force authentication involves repeated failed login attempts.",
        "PowerShell can be abused to execute malicious commands."
    ]

    embeddings = embedder.embed(sample_texts)

    print("===== EMBEDDING TEST =====")
    print(f"Number of texts: {len(sample_texts)}")
    print(f"Embedding shape: {embeddings.shape}")
    print(f"Embedding dimension: {embeddings.shape[1]}")
    print("Embedding test: PASSED")
