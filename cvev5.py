# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: Copyright 2024 Marta Rybczynska
# $ git init 
import json
import re
import csv
from pathlib import Path
from datetime import datetime
from dateutil.parser import parse
from dateutil.tz import UTC
from git import Repo
from cmp_version import cmp_version


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
    print("Writing results...")
    for pr in db:       
        line_datas = []
        commits = []
        semvers = []
       
        if pr[0].lower() == product and (
            (vendor == "*") or (vendor == pr[1]["vendor"].lower())
        ):  

            for x in pr[1] : 
                for y in x["versions"] :
                    if "versionType" in y:
                        if y["versionType"] == "git":
                            if "lessThan" in y: 
                                commits.append(y["lessThan"])
                        elif y["versionType"] == "semver" or y["versionType"] == "original_commit_for_fix":         
                            if y["version"] != "0":
                                semvers.append(y["version"])   
          
            # looking for CVE publication date
            cve_date, cve_hour = get_publication_date_from_CVE(pr)
                #writing them in the CSV file
            line_datas = [pr[3],"CVE", "PD", cve_date, cve_hour]
            write_date(result_file_path, line_datas)
            
            for commit in commits:
                
                #looking for each "lessThan" commit dates (author + committer)
                author_date, author_hour = get_author_date_from_commit(linux_repo, commit)
                committer_date, committer_hour = get_committer_date_from_commit(linux_repo, commit)
                release_date, release_hour = get_release_date_from_commit(linux_repo, commit, semvers)
                
                #writing author date in CSV file
                line_datas = [pr[3], commit, "AD", author_date, author_hour]
                write_date(result_file_path, line_datas)
                
                #writing committer date in CSV file
                line_datas = [pr[3], commit, "CD", committer_date, committer_hour]
                write_date(result_file_path, line_datas)
                
                #writing release date in CSV file
                line_datas = [pr[3], commit, "RD", release_date, release_hour]
                write_date(result_file_path, line_datas)
                
                del author_date, author_hour, committer_date, committer_hour
    print("Results writed")
    
def get_release_date_from_commit(repository, commit, semvers):
    commit_tag = get_commit_tag(repository, commit)
    semver = find_recentest_semver(semvers, commit_tag)
    commit_hash = get_commit_hash_from_semver(repository, semver)
    release_date, release_hour = get_committer_date_from_commit(repository, commit_hash)
    return release_date, release_hour
    
def get_commit_tag(repository, commit_num):
    repo=Repo(repository)
    commit_tag = repo.git.describe('--tags', commit_num)
    return clean_commit_tag(commit_tag)
    
def clean_commit_tag(commit_tag):
    clean_commit_tag = re.sub("[a-zA-Z]", "", commit_tag)
    clean_commit_tag = re.sub("-.*","", clean_commit_tag)
    return clean_commit_tag
   
    
def find_recentest_semver(semvers, commit_tag):
    recent_semvers = []
    for semver in semvers:
        if cmp_version(semver, commit_tag) == 1 or cmp_version(semver, commit_tag) == 0:
            recent_semvers.append(semver)
            
    closest_semver = recent_semvers[0]
    for semver in recent_semvers:
        if cmp_version(semver, closest_semver) == -1:
            closest_semver = semver
            
    return closest_semver

def get_commit_hash_from_semver(repository, semver):
    repo = Repo(repository)
    commit_hash = repo.git.rev_parse(f"v{semver}")
    return commit_hash
    
    
def get_author_date_from_commit(repository, commit):
    repo = Repo(repository)
    commit = repo.commit(commit)
    author_date, author_hour = parse_date(str(commit.authored_datetime.astimezone(UTC)))
    return author_date, author_hour

def get_committer_date_from_commit(repository, commit):
    repo = Repo(repository)
    commit = repo.commit(commit)
    commit_date, commit_hour = parse_date(str(commit.committed_datetime.astimezone(UTC)))
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
    

def create_commit_patch_db(db, product, vendor, version, year):
    patch_directory = Path.cwd()/"CVE_patchs"
    patch_directory.mkdir(exist_ok=True)
    
    print("Creating database...")
    for pr in db:
        commits = []
        
        if pr[0].lower() == product and (
            (vendor == "*") or (vendor == pr[1]["vendor"].lower())
        ):
            cve_patch_directory = patch_directory/(pr[3].strip('.json'))
            cve_patch_directory.mkdir(exist_ok=True)
            
            for x in pr[1] : 
                for y in x["versions"] :
                    if "versionType" in y:
                        if y["versionType"] == "git":
                            if "lessThan" in y: 
                                commits.append(y["lessThan"])
                
                
            for commit in commits:
                
                commit_file_json = cve_patch_directory/f"{commit}.json"
                commit_file_txt = cve_patch_directory/f"{commit}.txt"
                patch = load_patch(linux_repo, commit)
                if commit_file_json.exists() or commit_file_txt.exists():
                    commit_file_json.unlink()
                    commit_file_json.touch()
                    write_patch_json(commit_file_json, patch)
                    commit_file_txt.unlink()
                    commit_file_txt.touch()
                    write_patch_txt(commit_file_txt, patch) 
                else :
                    commit_file_json.touch()
                    write_patch_json(commit_file_json, patch)
                    commit_file_txt.touch()
                    write_patch_txt(commit_file_txt, patch)
    print("Database created")

               
def load_patch(repository, commit_num):
    repo = Repo(repository)
    commit = repo.commit(commit_num)
    patch = repo.git.diff(commit.parents[0], commit_num)
    return patch

def write_patch_json(file, patch):
    with open(file, "w") as f:
        json.dump(patch, f)

def write_patch_txt(file, patch):
    with open(file, "w") as f:
        f.writelines(patch)
