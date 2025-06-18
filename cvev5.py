# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: Copyright 2024 Marta Rybczynska
# $ git init 
import json
import os
import re
from pathlib import Path
from datetime import datetime
from dateutil.parser import parse
from git import Repo
import csv

cves_repo = "/home/paul.montoussy@Digital-Grenoble.local/gittedbase/stage/cvelistV5"
linux_repo = "/home/paul.montoussy@Digital-Grenoble.local/gittedbase/stage/linux"

def git_pull_repo(path):
    repo = Repo(path)
    repo.remotes.origin.pull()

def parse_cve_id_with_year(cve, minimal_year_wanted):
    pattern = pattern = r"CVE-(\d{4})-(\d+)\.json"
    match = re.match(pattern, cve)
    if match:
        cve_year = match.group(1)
        number = match.group(2)
        if cve_year < minimal_year_wanted:
            return None, None
        return cve_year, number
    else:
        return None, None

def get_dates(db, product, vendor, version, year):
    result_file_path = create_result_file(product, year)
    for pr in db:
        line_datas = []
        commits = []
        if pr[0].lower() == product and (
            (vendor == "*") or (vendor == pr[1]["vendor"].lower())
        ):
            for x in pr[1]["versions"] :
                for key in x :
                    if key == "lessThan":
                        commits.append(x[key])
            
            #looking for CVE publication date
            cve_date, cve_hour = get_publication_date_from_CVE(pr)
            line_datas = [pr[3],"CVE", "PD", cve_date, cve_hour]
                #writing them in the CSV file
            write_date(result_file_path, line_datas)
            print(pr[3])
            print("- CVE publication date : " + cve_date +" à " + cve_hour)
            
            #looking for each "lessThan" commit dates (author + committer)
            for commit in commits:
                author_date, author_hour = get_author_date_from_commit(linux_repo, commit)
                committer_date, committer_hour = get_committer_date_from_commit(linux_repo, commit)
                    #writing author date in CSV file
                line_datas = ["commit", commit, "AD", author_date, author_hour]
                write_date(result_file_path, line_datas)
                
                    #writing committer date in CSV file
                line_datas = ["commit", commit, "CD", committer_date, committer_hour]
                write_date(result_file_path, line_datas)
                print(f"Commit : {commit}")
                print("- Author date : " + author_date + " à " + author_hour)
                print("- Committer date : " + committer_date + " à " + committer_hour)
                del author_date, author_hour, committer_date, committer_hour

def get_author_date_from_commit(path, commit):
    repo = Repo(path)
    commit = repo.commit(commit)
    author_date, author_hour = parse_date(str(commit.authored_datetime))
    return author_date, author_hour

def get_committer_date_from_commit(path, commit):
    repo = Repo(path)
    commit = repo.commit(commit)
    commit_date, commit_hour = parse_date(str(commit.committed_datetime))
    return commit_date, commit_hour

def get_publication_date_from_CVE(pr):
    cve_date, cve_hour = parse_date(pr[2]["cveMetadata"]["datePublished"])
    return cve_date, cve_hour


def parse_date(date):
    parse_date = parse(date)
    parsed_date = parse_date.strftime('%Y-%m-%d')
    parsed_hour = parse_date.strftime('%H:%M')

    return parsed_date, parsed_hour

def create_result_file(product, year):
    path = Path.cwd()/"results"
    date = datetime.today().strftime('%Y-%m-%d')
    results_file_name = path/f"{date}_{product}_since{year}results.csv"

    path.mkdir(exist_ok=True)
    if results_file_name.exists():
        results_file_name.unlink()
        results_file_name.touch()
        print(f"\"{results_file_name.name}\" already exists : file replaced")
        return results_file_name
    else :
        results_file_name.touch()
        print(f"\"{results_file_name.name}\" file created")
        return results_file_name

def write_date(path, dates):
    with open(path, 'a', newline='') as csvfile:
        date_writer = csv.writer(csvfile, delimiter = ',', quotechar='|', quoting=csv.QUOTE_MINIMAL)
        date_writer.writerow(dates)
    

    
# def parse_cve_id(cve):
#     pattern = pattern = r"CVE-(\d{4})-(\d+)\.json"
#     match = re.match(pattern, cve)
#     if match:
#         year = match.group(1)
#         number = match.group(2)
#         return year, number
#     else:
#         return None, None

# def is_semver(version):
#     if version == "unspecified":
#         return True
#     if version == "0":
#         return True

#     version_parts = version.split(".")
#     if len(version_parts) == 3:
#         return True
#     return False


# def match_semver(version, target_version):
#     # Special case, 0 means "first available"
#     if version == "0":
#         return True

#     version_parts = version.split(".")
#     target_parts = target_version.split(".")

#     # Compare major and minor versions
#     if version_parts[0] == target_parts[0] and version_parts[1] == target_parts[1]:
#         return True
#     else:
#         return False


# def match_semver_less_equal(version, target_version):
#     version_parts = version.split(".")
#     target_parts = target_version.split(".")

#     # Compare major and minor versions
#     if version_parts[0] >= target_parts[0]:
#         return True

#     if version_parts[1] >= target_parts[1]:
#         return True

#     if version_parts[2] >= target_parts[2]:
#         return True

#     return False


# def match_semver_less(version, target_version):
#     version_parts = version.split(".")
#     target_parts = target_version.split(".")

#     # Compare major and minor versions
#     if version_parts[0] > target_parts[0]:
#         return True

#     if version_parts[1] > target_parts[1]:
#         return True

#     if version_parts[2] > target_parts[2]:
#         return True

#     return False


# def parse_cpe_entry(cpe_entry):
#     parts = cpe_entry.split(":")
#     vendor_name = parts[3]
#     product_name = parts[4]
#     version = parts[5]

#     if vendor_name == "*":
#         vendor_name = None
#     return vendor_name, product_name, version


# def is_affected(entries, version):
#     if "versions" not in entries:
#         if "defaultStatus" in entries:
#             if entries["defaultStatus"] == "affected":
#                 return "affected"
#             elif entries["defaultStatus"] == "unaffected":
#                 return "not affected"
#         return "unknown"

#     for entry in entries["versions"]:

#         # Entries like  'versions': [{'status': 'affected', 'version': '3.5.12'}]}
#         if (entry["status"] == "affected") and "versionType" not in entry:
#             if entry["version"] == version:
#                 return "affected"
#             # If has only one version, but doesn't match ours, try another entry
#             if is_semver(entry["version"]):
#                 continue
#             # Malformed/unsupported type of version
#             print("Malformed entry... skipping " + str(entry))
#             return "unknown"

#         # Malformed/unsupported version, skip parsing
#         if (entry["status"] == "affected") and not is_semver(entry["version"]):
#             print("Malformed entry... skipping " + str(entry))
#             return "unknown"

#         if (
#             (entry["status"] == "affected")
#             and (entry["versionType"] == "semver" or entry["versionType"] == "custom")
#             and match_semver(entry["version"], version)
#         ):
#             if "lessThanOrEqual" in entry:
#                 if match_semver_less_equal(entry["lessThanOrEqual"], version):
#                     return "affected"
#             elif "lessThan" in entry:
#                 if match_semver_less(entry["lessThan"], version):
#                     return "affected"

#     return "not affected"


# def get_status(db, product, vendor, version):
#     for pr in db:
#         if pr[0].lower() == product and (
#             (vendor == "*") or (vendor == pr[1]["vendor"].lower())
#         ):
#             vuln_status = is_affected(pr[1], version)
#             if vuln_status == "affected":
#                 print(pr[3] + ": affected: " + product + " " + version)
#             elif vuln_status == "unknown":
#                 print(pr[3] + ": unknown status: " + product + " " + version)
#             elif vuln_status == "not affected":
#                 print(pr[3] + ": not affected " + product + " " + version)
#             print()


