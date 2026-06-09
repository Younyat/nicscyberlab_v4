from __future__ import annotations

import pickle
from pathlib import Path
from statistics import mean

from flask import Blueprint, jsonify, request, send_from_directory

from ciberia_lab.services.config import DATA_SPLIT_FILES, FRAMEWORK_DIR, UPLOADS_DIR
from ciberia_lab.services.model_service import (
    activate_model,
    get_active_model_path,
    get_model,
)
from ciberia_lab.services.pcap_features import pcap_to_csv, pcap_to_dataframe
from ciberia_lab.services.predictor import predict_from_csv_file, predict_from_dataframe
from ciberia_lab.services.training_service import evaluate_active_model, train_default_model


bp = Blueprint(
    "ciberia_lab",
    __name__,
    url_prefix="/api/ciberia",
    template_folder="templates",
    static_folder="static",
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
APP_CORE_STATIC = PROJECT_ROOT / "app_core" / "static"

PROFILE_INFO = {
    "2017": {
        "profile": "2017",
        "title": "CIC-IDS2017",
        "notebook": "Framework.ipynb",
        "goal": "Model creation and analysis for CIC-IDS2017",
        "split_file": str(FRAMEWORK_DIR / "data_split_2017.pkl"),
        "base_model_file": str(FRAMEWORK_DIR / "stacked_model_original.pkl"),
        "mode": "baseline_framework_artifact",
    },
    "2018": {
        "profile": "2018",
        "title": "CIC-IDS2018",
        "notebook": "Framework copy.ipynb",
        "goal": "Model creation and analysis for CIC-IDS2018",
        "split_file": str(FRAMEWORK_DIR / "data_split_2018.pkl"),
        "base_model_file": str(FRAMEWORK_DIR / "stacked_model_original.pkl"),
        "mode": "framework_profile",
    },
    "unsw": {
        "profile": "unsw",
        "title": "UNSW-NB15",
        "notebook": "Framework copy 2.ipynb",
        "goal": "Model creation and analysis for UNSW-NB15",
        "split_file": str(FRAMEWORK_DIR / "data_split_unsw.pkl"),
        "base_model_file": str(FRAMEWORK_DIR / "stacked_model_original.pkl"),
        "mode": "framework_profile",
    },
}


def _load_split(dataset: str) -> dict:
    dataset = dataset.lower()
    if dataset not in DATA_SPLIT_FILES:
        raise ValueError(f"Unsupported dataset: {dataset}")
    with open(DATA_SPLIT_FILES[dataset], "rb") as f:
        return pickle.load(f)


def _classification_rows(classification_report: dict) -> list[dict]:
    rows = []
    for k, v in classification_report.items():
        if isinstance(v, dict) and "precision" in v:
            rows.append(
                {
                    "label": k,
                    "precision": v.get("precision"),
                    "recall": v.get("recall"),
                    "f1_score": v.get("f1-score"),
                    "support": v.get("support"),
                }
            )
    return rows


def _evaluation_summary(result: dict) -> dict:
    report = result.get("classification_report", {})
    class_rows = [
        (k, v)
        for k, v in report.items()
        if isinstance(v, dict) and "f1-score" in v and k not in {"macro avg", "weighted avg"}
    ]

    sorted_rows = sorted(class_rows, key=lambda x: x[1]["f1-score"], reverse=True)

    strongest = []
    for label, values in sorted_rows[:3]:
        strongest.append(
            {
                "label": label,
                "f1_score": values["f1-score"],
                "precision": values["precision"],
                "recall": values["recall"],
            }
        )

    weakest = []
    for label, values in sorted_rows[-3:]:
        weakest.append(
            {
                "label": label,
                "f1_score": values["f1-score"],
                "precision": values["precision"],
                "recall": values["recall"],
            }
        )

    return {
        "accuracy": result.get("accuracy"),
        "macro_f1": result.get("macro_f1"),
        "rows": result.get("rows"),
        "strongest_classes": strongest,
        "weakest_classes": weakest,
        "interpretation": (
            "This result shows that the framework artifact is operational on its prepared split. "
            "High agreement here validates artifact loading, dataset compatibility, and evaluation workflow."
        ),
    }


def _prediction_summary(prediction_result: dict) -> dict:
    results = prediction_result.get("results", [])
    summary = prediction_result.get("summary", {})

    confidences = [r.get("confidence") for r in results if r.get("confidence") is not None]
    avg_conf = mean(confidences) if confidences else None

    dominant_class = None
    dominant_count = 0
    if summary:
        dominant_class = max(summary, key=summary.get)
        dominant_count = summary[dominant_class]

    diversity = len(summary.keys())

    interpretation = (
        "Predictions were generated successfully. "
        "This demonstrates operational inference on the provided feature table."
    )

    if diversity == 1:
        interpretation += (
            " All rows collapsed into a single class. "
            "This may indicate genuinely homogeneous traffic, limited class diversity, "
            "or feature distributions concentrated in one region of the model space."
        )

    return {
        "input_rows": prediction_result.get("input_rows"),
        "dominant_class": dominant_class,
        "dominant_count": dominant_count,
        "class_diversity": diversity,
        "average_confidence": avg_conf,
        "interpretation": interpretation,
    }


@bp.route("/health", methods=["GET"])
def health():
    return jsonify({"ok": True, "module": "ciberia"}), 200


@bp.route("/profiles", methods=["GET"])
def profiles():
    return jsonify(
        {
            "ok": True,
            "profiles": list(PROFILE_INFO.values()),
            "message": (
                "Framework profiles represent dataset-oriented artifacts derived from the repository notebooks. "
                "Prepared splits are the primary validation path. PCAP conversion is an alternative inference path."
            ),
        }
    ), 200


@bp.route("/status", methods=["GET"])
def status():
    model = get_model()
    payload = {
        "ok": True,
        "active_model_path": get_active_model_path(),
        "available_datasets": list(DATA_SPLIT_FILES.keys()),
        "classes": model.classes_.tolist() if hasattr(model, "classes_") else [],
        "n_features_in": int(model.n_features_in_) if hasattr(model, "n_features_in_") else None,
        "feature_names_in": model.feature_names_in_.tolist() if hasattr(model, "feature_names_in_") else [],
        "message": "Active framework artifact loaded successfully.",
    }
    return jsonify(payload), 200


@bp.route("/baseline/evaluate", methods=["POST"])
def baseline_evaluate():
    try:
        body = request.get_json(silent=True) or {}
        dataset = str(body.get("dataset", "2017")).lower()

        model = get_model()
        result = evaluate_active_model(model, dataset=dataset)
        result["profile"] = PROFILE_INFO.get(dataset, {})
        result["summary_explanation"] = _evaluation_summary(result)
        result["classification_rows"] = _classification_rows(result.get("classification_report", {}))
        result["mode"] = "baseline_reproduction"
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@bp.route("/baseline/export-sample-csv", methods=["GET"])
def baseline_export_sample_csv():
    try:
        dataset = str(request.args.get("dataset", "2017")).lower()
        split = str(request.args.get("split", "test")).lower()
        rows = int(request.args.get("rows", "50"))
        include_label = str(request.args.get("include_label", "1")) == "1"

        if dataset not in DATA_SPLIT_FILES:
            return jsonify({"ok": False, "error": f"Invalid dataset: {dataset}"}), 400

        data = _load_split(dataset)

        x_key = "X_test" if split == "test" else "X_train"
        y_key = "y_test" if split == "test" else "y_train"

        df = data[x_key].head(rows).copy()
        if include_label:
            df["Attack Type"] = data[y_key].head(rows).values

        out_path = FRAMEWORK_DIR / f"sample_{dataset}_{split}_{rows}.csv"
        df.to_csv(out_path, index=False)

        return jsonify(
            {
                "ok": True,
                "dataset": dataset,
                "profile": PROFILE_INFO.get(dataset, {}),
                "split": split,
                "rows": int(len(df)),
                "csv_file": str(out_path),
                "preview": df.head(20).to_dict(orient="records"),
                "mode": "prepared_framework_csv",
                "message": (
                    "This CSV is derived from the prepared split artifact and is suitable for controlled inference validation."
                ),
            }
        ), 200
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@bp.route("/retrain", methods=["POST"])
def retrain():
    try:
        body = request.get_json(silent=True) or {}
        dataset = str(body.get("dataset", "2017")).lower()
        set_active = bool(body.get("set_active", True))

        result = train_default_model(dataset=dataset, set_active=set_active)
        result["profile"] = PROFILE_INFO.get(dataset, {})
        result["summary_explanation"] = _evaluation_summary(
            {
                "accuracy": result.get("accuracy"),
                "macro_f1": result.get("macro_f1"),
                "rows": 21000 if dataset == "2017" else None,
                "classification_report": result.get("classification_report", {}),
            }
        )
        result["classification_rows"] = _classification_rows(result.get("classification_report", {}))
        result["mode"] = "retrained_framework_artifact"
        result["message"] = "Retraining completed and the new artifact was generated successfully."
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@bp.route("/predict-csv", methods=["POST"])
def predict_csv():
    try:
        if "file" not in request.files:
            return jsonify({"ok": False, "error": "Missing uploaded file in form field 'file'"}), 400

        uploaded_file = request.files["file"]
        if uploaded_file.filename == "":
            return jsonify({"ok": False, "error": "Empty filename"}), 400

        result = predict_from_csv_file(uploaded_file)
        result["mode"] = "prepared_or_user_csv_inference"
        result["summary_explanation"] = _prediction_summary(result)
        result["message"] = (
            "CSV inference completed. Use prepared CSV files from framework splits as the primary validation path."
        )
        return jsonify(result), 200

    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@bp.route("/extract-from-pcap", methods=["POST"])
def extract_from_pcap():
    try:
        if "file" not in request.files:
            return jsonify({"ok": False, "error": "Missing uploaded file in form field 'file'"}), 400

        uploaded_file = request.files["file"]
        if uploaded_file.filename == "":
            return jsonify({"ok": False, "error": "Empty filename"}), 400

        tmp_path = UPLOADS_DIR / uploaded_file.filename
        uploaded_file.save(tmp_path)

        result = pcap_to_csv(tmp_path)
        result["mode"] = "alternative_pcap_conversion"
        result["warning"] = (
            "This conversion is an operational alternative when prepared CSV files are not available. "
            "It is not guaranteed to be fully identical to the original notebook preprocessing pipeline."
        )
        result["message"] = "PCAP conversion completed successfully."
        return jsonify(result), 200

    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@bp.route("/predict-pcap", methods=["POST"])
def predict_pcap():
    try:
        if "file" not in request.files:
            return jsonify({"ok": False, "error": "Missing uploaded file in form field 'file'"}), 400

        uploaded_file = request.files["file"]
        if uploaded_file.filename == "":
            return jsonify({"ok": False, "error": "Empty filename"}), 400

        tmp_path = UPLOADS_DIR / uploaded_file.filename
        uploaded_file.save(tmp_path)

        df = pcap_to_dataframe(tmp_path)
        result = predict_from_dataframe(df)
        result["generated_rows"] = int(len(df))
        result["source_pcap"] = str(tmp_path)
        result["mode"] = "alternative_pcap_inference"
        result["warning"] = (
            "Predictions are based on an approximate PCAP-to-feature conversion path. "
            "Prepared framework CSVs remain the preferred validation route."
        )
        result["summary_explanation"] = _prediction_summary(result)
        result["message"] = "PCAP inference completed successfully."
        return jsonify(result), 200

    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@bp.route("/ui", methods=["GET"])
def ui():
    return send_from_directory(APP_CORE_STATIC, "ciberia_lab.html")


@bp.route("/ui/static/js/<path:filename>", methods=["GET"])
def ui_static_js(filename):
    return send_from_directory(APP_CORE_STATIC / "js", filename)


@bp.route("/ui/static/css/<path:filename>", methods=["GET"])
def ui_static_css(filename):
    return send_from_directory(APP_CORE_STATIC / "css", filename)