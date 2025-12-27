#!/usr/bin/env python3
"""Download and prepare US city/state data for offline geocoding."""

from __future__ import annotations

import csv
import os
import pathlib
import urllib.error
import urllib.request

DATA_URLS = [
    os.environ.get("HELPER_PLACES_URL", "").strip(),
    "https://www2.census.gov/geo/docs/maps-data/data/gazetteer/2024_Gazetteer/2024_gazetteer_places_national.txt",
    "https://www2.census.gov/geo/docs/maps-data/data/gazetteer/2023_Gazetteer/2023_gazetteer_places_national.txt",
    "https://www2.census.gov/geo/docs/maps-data/data/gazetteer/2022_Gazetteer/2022_gazetteer_places_national.txt",
    "https://www2.census.gov/geo/docs/maps-data/data/gazetteer/2021_Gazetteer/2021_gazetteer_places_national.txt",
]
TARGET_DIR = pathlib.Path(__file__).resolve().parent
RAW_PATH = TARGET_DIR / "gazetteer_places_national.txt"
ALT_RAW_PATH = TARGET_DIR / "2024_Gaz_place_national.txt"
OUTPUT_PATH = TARGET_DIR / "us_places.csv"


def _get_field(row: dict[str, str], keys: list[str]) -> str:
    for key in keys:
        value = row.get(key)
        if value is not None:
            return value
    return ""


def download_dataset() -> None:
    if RAW_PATH.exists() or ALT_RAW_PATH.exists():
        return
    urls = [url for url in DATA_URLS if url]
    errors: list[str] = []
    for url in urls:
        try:
            print(f"Downloading {url}...")
            urllib.request.urlretrieve(url, RAW_PATH)
            print(f"Downloaded dataset from {url}")
            return
        except urllib.error.HTTPError as exc:
            errors.append(f"{url} -> HTTP {exc.code}")
            if exc.code == 404:
                continue
            raise
        except urllib.error.URLError as exc:
            errors.append(f"{url} -> {exc.reason}")
            continue
    summary = "; ".join(errors) if errors else "No URLs available."
    raise RuntimeError(f"Failed to download dataset. Tried: {summary}")


def build_dataset() -> None:
    source_path = RAW_PATH if RAW_PATH.exists() else ALT_RAW_PATH
    if not source_path.exists():
        raise RuntimeError("No raw gazetteer file found. Download one first.")
    with source_path.open("r", encoding="utf-8", newline="") as handle:
        raw_reader = csv.reader(handle, delimiter="\t")
        header = next(raw_reader, [])
        cleaned_header = [value.strip() for value in header]
        reader = csv.DictReader(handle, fieldnames=cleaned_header, delimiter="\t")
        with OUTPUT_PATH.open("w", encoding="utf-8", newline="") as output:
            writer = csv.DictWriter(
                output,
                fieldnames=["city", "state", "lat", "lon", "population"],
            )
            writer.writeheader()
            for row in reader:
                city = _get_field(row, ["NAME", "NAMELSAD"])
                state = _get_field(row, ["USPS", "STUSPS", "STATE"])
                lat = _get_field(row, ["INTPTLAT", "INTPTLAT10", "LAT"])
                lon = _get_field(row, ["INTPTLONG", "INTPTLON", "LON", "LONG"])
                population = _get_field(row, ["POP2020", "POPULATION", "POP"])
                if not city or not state or not lat or not lon:
                    continue
                writer.writerow(
                    {
                        "city": city.strip(),
                        "state": state.strip().upper(),
                        "lat": lat.strip(),
                        "lon": lon.strip(),
                        "population": population.strip() if population else "0",
                    }
                )


def main() -> None:
    download_dataset()
    build_dataset()
    print(f"Wrote {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
