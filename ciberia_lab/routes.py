from __future__ import annotations

import pickle
from pathlib import Path
from statistics import mean

from flask import Blueprint, jsonify, request, send_from_directory

from ciberia_lab.services.config import FRAMEWORK_DIR, UPLOADS_DIR
from ciberia_lab.services.custom_datasets import (
    delete_custom_dataset,
    get_all_profiles,
    get_all_split_files,
    import_custom_split_dataset,
)
from ciberia_lab.services.model_service import get_active_model_path, get_model
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


def _profile_info() -> dict:
    return get_all_profiles()


def _load_split(dataset: str) -> dict:
    dataset = dataset.lower()
    all_splits = get_all_split_files()

    if dataset not in all_splits:
        raise ValueError(f"Unsupported dataset: {dataset}")

    with open(all_splits[dataset], "rb") as f:
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
            "profiles": list(_profile_info().values()),
            "message": (
                "Framework profiles represent dataset-oriented artifacts derived from the repository notebooks. "
                "Prepared splits are the primary validation path. "
                "PCAP conversion is an alternative inference path."
            ),
        }
    ), 200


@bp.route("/status", methods=["GET"])
def status():
    model = get_model()
    payload = {
        "ok": True,
        "active_model_path": get_active_model_path(),
        "available_datasets": list(get_all_split_files().keys()),
        "profiles": list(_profile_info().values()),
        "classes": model.classes_.tolist() if hasattr(model, "classes_") else [],
        "n_features_in": int(model.n_features_in_) if hasattr(model, "n_features_in_") else None,
        "feature_names_in": model.feature_names_in_.tolist() if hasattr(model, "feature_names_in_") else [],
        "message": "Active framework artifact loaded successfully.",
    }
    return jsonify(payload), 200


@bp.route("/datasets/custom/status", methods=["GET"])
def custom_datasets_status():
    try:
        custom_profiles = [
            profile for profile in _profile_info().values()
            if profile.get("source") == "custom"
        ]

        payload = {
            "ok": True,
            "custom_dataset_count": len(custom_profiles),
            "custom_datasets": custom_profiles,
            "available_custom_dataset_ids": [p.get("profile") for p in custom_profiles],
            "message": "Custom dataset artifacts loaded successfully.",
        }
        return jsonify(payload), 200
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@bp.route("/datasets/import-split", methods=["POST"])
def datasets_import_split():
    try:
        if "file" not in request.files:
            return jsonify({"ok": False, "error": "Missing uploaded file in form field 'file'"}), 400

        uploaded_file = request.files["file"]
        if uploaded_file.filename == "":
            return jsonify({"ok": False, "error": "Empty filename"}), 400

        dataset_name = str(request.form.get("dataset_name", "")).strip()
        dataset_id = str(request.form.get("dataset_id", "")).strip() or None
        label_column = str(request.form.get("label_column", "Attack Type")).strip() or "Attack Type"

        result = import_custom_split_dataset(
            file_storage=uploaded_file,
            dataset_name=dataset_name,
            dataset_id=dataset_id,
            label_column=label_column,
        )

        result["profiles"] = list(_profile_info().values())
        return jsonify(result), 200
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@bp.route("/datasets/delete", methods=["POST"])
def datasets_delete():
    try:
        body = request.get_json(silent=True) or {}
        dataset = str(body.get("dataset", "")).strip().lower()
        result = delete_custom_dataset(dataset)
        result["profiles"] = list(_profile_info().values())
        return jsonify(result), 200
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    except FileNotFoundError as e:
        return jsonify({"ok": False, "error": str(e)}), 404
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@bp.route("/baseline/evaluate", methods=["POST"])
def baseline_evaluate():
    try:
        body = request.get_json(silent=True) or {}
        dataset = str(body.get("dataset", "2017")).lower()
        model = get_model()

        result = evaluate_active_model(model, dataset=dataset)
        result["profile"] = _profile_info().get(dataset, {})
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

        all_splits = get_all_split_files()
        if dataset not in all_splits:
            return jsonify({"ok": False, "error": f"Invalid dataset: {dataset}"}), 400

        data = _load_split(dataset)
        x_key = "X_test" if split == "test" else "X_train"
        y_key = "y_test" if split == "test" else "y_train"

        df = data[x_key].head(rows).copy()

        profile = _profile_info().get(dataset, {})
        label_column = profile.get("label_column", "Attack Type")

        if include_label:
            df[label_column] = data[y_key].head(rows).values

        out_path = FRAMEWORK_DIR / f"sample_{dataset}_{split}_{rows}.csv"
        df.to_csv(out_path, index=False)

        return jsonify(
            {
                "ok": True,
                "dataset": dataset,
                "profile": profile,
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
        result["profile"] = _profile_info().get(dataset, {})
        result["summary_explanation"] = _evaluation_summary(
            {
                "accuracy": result.get("accuracy"),
                "macro_f1": result.get("macro_f1"),
                "rows": result.get("rows"),
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
        result["message"] = "CSV inference completed. Use prepared CSV files from framework splits as the primary validation path."
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




from ciberia_lab.services.pcap_dataset_builder import build_split_from_pcap
from werkzeug.utils import secure_filename
import os


@bp.route("/datasets/import-from-pcap", methods=["POST"])
def datasets_import_from_pcap():
    try:
        if "file" not in request.files:
            return jsonify({"ok": False, "error": "Missing uploaded file in form field 'file'"}), 400

        uploaded_file = request.files["file"]
        if uploaded_file.filename == "":
            return jsonify({"ok": False, "error": "Empty filename"}), 400

        dataset_name = str(request.form.get("dataset_name", "")).strip()
        dataset_id = str(request.form.get("dataset_id", "")).strip()
        label = str(request.form.get("label", "")).strip() or None
        auto_label = str(request.form.get("auto_label", "0")).strip() == "1"
        label_column = str(request.form.get("label_column", "Attack Type")).strip() or "Attack Type"
        test_size = float(request.form.get("test_size", "0.30"))
        flow_timeout = float(request.form.get("flow_timeout", "120"))
        activity_timeout = float(request.form.get("activity_timeout", "5"))

        if not dataset_name:
            return jsonify({"ok": False, "error": "dataset_name is required"}), 400

        if not dataset_id:
            return jsonify({"ok": False, "error": "dataset_id is required"}), 400

        safe_name = secure_filename(uploaded_file.filename)
        tmp_path = UPLOADS_DIR / safe_name
        uploaded_file.save(tmp_path)

        try:
            built = build_split_from_pcap(
                pcap_path=str(tmp_path),
                dataset_id=dataset_id,
                label=label,
                auto_label=auto_label,
                test_size=test_size,
                flow_timeout=flow_timeout,
                activity_timeout=activity_timeout,
            )

            split_path = Path(built["split_path"])

            from ciberia_lab.services.custom_datasets import _write_json, _metadata_path

            metadata = {
                "profile": dataset_id,
                "title": dataset_name,
                "goal": "Custom dataset generated from uploaded PCAP in CiberIA Lab",
                "label_column": label_column,
                "imported_at_utc": __import__("datetime").datetime.utcnow().isoformat() + "Z",
                "rows_train": built["rows_train"],
                "rows_test": built["rows_test"],
                "features": built["features"],
                "labels": built["labels"],
                "label_distribution": built["label_distribution"],
                "original_filename": uploaded_file.filename or "",
                "source_type": "pcap_generated",
                "split_file": str(split_path),
            }

            _write_json(_metadata_path(dataset_id), metadata)

            result = {
                "ok": True,
                "dataset": metadata,
                "split_file": str(split_path),
                "rows_total": built["rows_total"],
                "message": "Custom dataset generated from PCAP successfully.",
                "profiles": list(_profile_info().values()),
            }
            return jsonify(result), 200
        finally:
            if tmp_path.exists():
                tmp_path.unlink(missing_ok=True)

    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500