from pathlib import Path
import unittest

from streamlit.testing.v1 import AppTest


APP_PATH = Path(__file__).resolve().parents[1] / "app.py"


def run_app() -> AppTest:
    return AppTest.from_file(APP_PATH, default_timeout=20).run(timeout=20)


def choose_input(app: AppTest, mode: str) -> AppTest:
    input_mode = next(item for item in app.selectbox if item.label == "Input mode")
    input_mode.set_value(mode)
    return app.run(timeout=20)


class StreamlitAppTests(unittest.TestCase):
    def test_event_replay_distinguishes_accepted_and_scoreable_events(self):
        app = choose_input(run_app(), "Replay bundled sample events")
        self.assertFalse(app.exception)
        metrics = {item.label: item.value for item in app.metric}
        self.assertEqual(metrics["Accepted events"], "5")
        self.assertEqual(metrics["Usable for scoring"], "5")
        self.assertTrue(
            any("Device records with missing scoring data:" in item.value for item in app.caption)
        )

    def test_csv_upload_classification_and_combined_filters(self):
        app = choose_input(run_app(), "Upload device-summary CSV")
        csv_data = (
            b"device,failed_connections,external_connections,unusual_port,bytes_out\n"
            b"Needle-high,10,20,0,0\n"
            b"Needle-review,10,0,0,0\n"
            b"Other-zero,0,0,0,0\n"
        )
        app.file_uploader[0].set_value(("triage.csv", csv_data, "text/csv"))
        app.run(timeout=20)
        self.assertFalse(app.exception)
        self.assertEqual(len(app.dataframe[0].value), 3)

        search = next(item for item in app.text_input if item.label == "Search devices")
        classification = next(item for item in app.selectbox if item.label == "Risk classification")
        search.set_value("needle")
        classification.set_value("High-priority review")
        app.run(timeout=20)
        self.assertEqual(app.dataframe[0].value["device"].tolist(), ["Needle-high"])
        self.assertFalse(app.get("download_button")[0].disabled)

    def test_csv_missing_columns_is_reported_without_app_failure(self):
        app = choose_input(run_app(), "Upload device-summary CSV")
        app.file_uploader[0].set_value(
            ("incomplete.csv", b"device,failed_connections\nnode,2\n", "text/csv")
        )
        app.run(timeout=20)
        self.assertFalse(app.exception)
        self.assertTrue(any("missing required columns" in item.value for item in app.error))
        self.assertTrue(app.dataframe[0].value.empty)


if __name__ == "__main__":
    unittest.main()
