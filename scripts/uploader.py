from pathlib import Path

from huggingface_hub import HfApi

api = HfApi()
file_path = Path("data/bronze/epss/run_20261113_190917Z/epss_scores.csv")
print("File exists:", file_path.exists())
print("File size:", round(file_path.stat().st_size / (1024**3), 2), "GB")
api.upload_file(
    path_or_fileobj=str(file_path),
    path_in_repo="epss_scores.csv",
    repo_id="patchledger/patchledger-data",
    repo_type="dataset",
)
print("Upload completed!")
