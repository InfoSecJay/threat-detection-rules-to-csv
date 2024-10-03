import os
import csv
import requests
import yaml
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

# GitHub repository URL
github_api_url = "https://api.github.com/repos/SigmaHQ/sigma/contents/rules"

# GitHub API Token
github_token = os.getenv("github_token")

# Get the current date in the specified format
current_date = datetime.now().strftime("%d_%m_%Y")

# Output CSV file with the current date in the name
output_csv = f"sigma_rules_export_{current_date}.csv"


# List of files to exclude
excluded_files = [
    "driver_load_win_mal_drivers.yml",
    "driver_load_win_mal_drivers_names.yml",
    "driver_load_win_vuln_drivers.yml",
    "driver_load_win_vuln_drivers_names.yml"
]


# Function to fetch YAML file content from GitHub API
def fetch_yaml_content(url):
    headers = {"Authorization": f"token {github_token}"}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        yaml_content = yaml.safe_load(response.text)
        return yaml_content
    else:
        print(f"Failed to fetch YAML content from {url}. Status code: {response.status_code}")
        return None




# Function to recursively fetch and parse YAML files
def scrape_yaml_files(url):
    headers = {"Authorization": f"token {github_token}"}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()

        yaml_data = []

        for item in data:
            if item["type"] == "file" and item["name"].endswith(".yml"):
                yaml_file = item["name"]
                
                # Skip the file if it's in the excluded list
                if yaml_file in excluded_files:
                    print(f"Skipping {yaml_file} as it is in the exclusion list.")
                    continue

                yaml_url = item["download_url"]
                folder_location = os.path.dirname(item["path"])

                yaml_content = fetch_yaml_content(yaml_url)

                if yaml_content is not None:
                    print(f"Fetching and parsing {yaml_file}...")

                    logsource = yaml_content.get("logsource", {})
                    product = logsource.get("product", "")
                    category = logsource.get("category", "")
                    author = yaml_content.get("author", "")

                    yaml_data.append({
                        "GitHub Folder Location": folder_location,
                        "GitHub File Name": yaml_file,
                        "Title": yaml_content.get("title", ""),
                        "ID": yaml_content.get("id", ""),
                        "Status": yaml_content.get("status", ""),
                        "Description": yaml_content.get("description", ""),
                        "Date": yaml_content.get("date", ""),
                        "Modified": yaml_content.get("modified", ""),
                        "Tags": yaml_content.get("tags", ""),
                        "Product": product,
                        "Category": category,
                        "Author": author,
                        "Detection": yaml_content.get("detection", ""),
                        "Falsepositives": yaml_content.get("falsepositives", ""),
                        "Level": yaml_content.get("level", "")
                    })
                else:
                    print(f"Skipping {yaml_file} due to an error while fetching content.")
            elif item["type"] == "dir":
                subfolder_url = item["url"]
                subfolder_data = scrape_yaml_files(subfolder_url)
                yaml_data.extend(subfolder_data)

        return yaml_data
    else:
        print(f"Failed to fetch data from {url}. Status code: {response.status_code}")
        return []


# Main function
def main():
    yaml_data = scrape_yaml_files(github_api_url)

    if yaml_data:
        # Write to CSV with the current date in the name
        with open(output_csv, mode="w", newline="", encoding="utf-8") as csv_file:
            fieldnames = [
                "GitHub Folder Location",
                "GitHub File Name",
                "Title",
                "ID",
                "Status",
                "Description",
                "Date",
                "Modified",
                "Tags",
                "Product",
                "Category",
                "Author",
                "Detection",
                "Falsepositives",
                "Level"
            ]
            writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(yaml_data)
            print(f"CSV file '{output_csv}' created successfully.")
    else:
        print("No YAML files were fetched.")


if __name__ == "__main__":
    main()
