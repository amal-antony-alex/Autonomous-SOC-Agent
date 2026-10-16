import json
import re
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[3]

INPUT_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "mitre_attack"
    / "mitre_techniques.jsonl"
)

OUTPUT_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "mitre_attack"
    / "mitre_corpus_clean.txt"
)


def clean_text(text):

    if not text:
        return ""

    # Remove HTML/code tags.
    text = re.sub(
        r"<[^>]+>",
        " ",
        text,
    )

    # Convert Markdown links to their visible text.
    text = re.sub(
        r"\[([^\]]+)\]\([^)]+\)",
        r"\1",
        text,
    )

    # Remove citation markers.
    text = re.sub(
        r"\(Citation:[^)]+\)",
        " ",
        text,
    )

    # Remove excessive whitespace.
    text = re.sub(
        r"\s+",
        " ",
        text,
    )

    return text.strip()


def main():

    print(
        "===== CLEANING MITRE CORPUS ====="
    )

    with open(
        INPUT_FILE,
        "r",
        encoding="utf-8",
    ) as file:

        rows = [
            json.loads(line)
            for line in file
            if line.strip()
        ]

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8",
    ) as file:

        for row in rows:

            technique_id = row[
                "technique_id"
            ]

            name = clean_text(
                row["name"]
            )

            description = clean_text(
                row["description"]
            )

            tactics = [
                clean_text(tactic)
                for tactic in row.get(
                    "tactics",
                    []
                )
            ]

            platforms = [
                clean_text(platform)
                for platform in row.get(
                    "platforms",
                    []
                )
            ]

            file.write(
                f"MITRE ATT&CK Technique: "
                f"{technique_id}\n"
            )

            file.write(
                f"Name: {name}\n"
            )

            file.write(
                f"Description: "
                f"{description}\n"
            )

            if tactics:

                file.write(
                    "Tactics: "
                    + ", ".join(tactics)
                    + "\n"
                )

            if platforms:

                file.write(
                    "Platforms: "
                    + ", ".join(platforms)
                    + "\n"
                )

            file.write("\n")

    print(
        f"Techniques processed: "
        f"{len(rows)}"
    )

    print(
        f"Clean corpus:\n"
        f"{OUTPUT_FILE}"
    )

    print(
        "===== MITRE CLEANING COMPLETE ====="
    )


if __name__ == "__main__":
    main()

