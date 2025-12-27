US location dataset

This folder holds the offline city/state dataset used for location search.

To build the dataset:
  python Server/location_data/fetch_us_places.py

This downloads the public-domain US Gazetteer places file and writes
Server/location_data/us_places.csv.

If you want to use a different source URL, set HELPER_PLACES_URL.
