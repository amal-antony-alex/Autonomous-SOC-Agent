import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[3]

INPUT_FILE = (
    PROJECT_ROOT
    / "data"
    / "raw"
    / "mitre_attack"
    / "enterprise-attack-19.2.json"
)

OUTPUT_CORPUS = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "mitre_attack"
    / "mitre_corpus.txt"
)

OUTPUT_JSONL = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "mitre_attack"
    / "mitre_techniques.jsonl"
)


def get_external_id(obj):

    for reference in obj.get(
        "external_references",
        []
    ):

        external_id = reference.get(
            "external_id"
        )

        if external_id and external_id.startswith(
            "T"
        ):
            return external_id

    return None


def clean_text(text):

    if not text:
        return ""

    return (
        text
        .replace("\r", " ")
        .replace("\n", " ")
        .replace("\t", " ")
    )


def main():

    print(
        "===== MITRE ATT&CK PARSER ====="
    )

    with open(
        INPUT_FILE,
        "r",
        encoding="utf-8",
    ) as file:

        bundle = json.load(file)

    objects = bundle.get(
        "objects",
        []
    )

    techniques = []

    for obj in objects:

        if obj.get("type") != "attack-pattern":
            continue

        if obj.get("revoked", False):
            continue

        if obj.get("x_mitre_deprecated", False):
            continue

        technique_id = get_external_id(
            obj
        )

        if not technique_id:
            continue

        name = obj.get(
            "name",
            ""
        ).strip()

        description = clean_text(
            obj.get(
                "description",
                ""
            )
        )

        if not name or not description:
            continue

        tactics = []

        for kill_chain_phase in obj.get(
            "kill_chain_phases",
            []
        ):

            phase = kill_chain_phase.get(
                "phase_name"
            )

            if phase:
                tactics.append(
                    phase.replace(
                        "-",
                        " "
                    )
                )

        platforms = obj.get(
            "x_mitre_platforms",
            []
        )

        detection = clean_text(
            obj.get(
                "x_mitre_detection",
                ""
            )
        )

        technique = {
            "technique_id": technique_id,
            "name": name,
            "description": description,
            "tactics": tactics,
            "platforms": platforms,
            "detection": detection,
        }

        techniques.append(
            technique
        )

    # Remove duplicate technique IDs
    unique = {}

    for technique in techniques:

        unique[
            technique["technique_id"]
        ] = technique

    techniques = list(
        unique.values()
    )

    techniques.sort(
        key=lambda x: x[
            "technique_id"
        ]
    )

    OUTPUT_CORPUS.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    OUTPUT_JSONL.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    # JSONL output
    with open(
        OUTPUT_JSONL,
        "w",
        encoding="utf-8",
    ) as file:

        for technique in techniques:

            file.write(
                json.dumps(
                    technique,
                    ensure_ascii=False
                )
                + "\n"
            )

    # Plain cybersecurity corpus
    with open(
        OUTPUT_CORPUS,
        "w",
        encoding="utf-8",
    ) as file:

        for technique in techniques:

            file.write(
                f"MITRE ATT&CK Technique: "
                f"{technique['technique_id']}\n"
            )

            file.write(
                f"Name: "
                f"{technique['name']}\n"
            )

            file.write(
                f"Description: "
                f"{technique['description']}\n"
            )

            if technique["tactics"]:

                file.write(
                    "Tactics: "
                    + ", ".join(
                        technique["tactics"]
                    )
                    + "\n"
                )

            if technique["platforms"]:

                file.write(
                    "Platforms: "
                    + ", ".join(
                        technique["platforms"]
                    )
                    + "\n"
                )

            if technique["detection"]:

                file.write(
                    "Detection: "
                    + technique["detection"]
                    + "\n"
                )

            file.write("\n")

    print(
        f"Total STIX objects: "
        f"{len(objects)}"
    )

    print(
        f"Valid ATT&CK techniques: "
        f"{len(techniques)}"
    )

    print()
    print(
        f"JSONL output:\n"
        f"{OUTPUT_JSONL}"
    )

    print()
    print(
        f"Corpus output:\n"
        f"{OUTPUT_CORPUS}"
    )

    print()
    print(
        "===== MITRE PARSING COMPLETE ====="
    )


if __name__ == "__main__":
    main()
