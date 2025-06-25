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
from product import product


cves_repo = "/home/paul.montoussy@Digital-Grenoble.local/gittedbase/stage/repos/cvelistV5"
linux_repo = "/home/paul.montoussy@Digital-Grenoble.local/gittedbase/stage/repos/linux"
zulip_repo = "/home/paul.montoussy@Digital-Grenoble.local/gittedbase/stage/repos/zulip"

def git_pull_repo(path):
    repo = Repo(path)
    repo.remotes.origin.pull()

#sorts entries with the date given as argument
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
                if "versions" in x: 
                    for y in x["versions"] :
                        if "versionType" in y:
                            if y["versionType"] == "git":
                                if "lessThan" in y: 
                                    commits.append(y["lessThan"])
                            elif y["versionType"] == "semver" or y["versionType"] == "original_commit_for_fix":         
                                if y["status"] == "unaffected":
                                    if y["version"] != "0":
                                        semvers.append(y["version"])   
                                elif y["status"] == "affected":
                                    semvers.append(y["lessThan"])
            
            # looking for CVE publication date
            cve_date, cve_hour = get_publication_date_from_CVE(pr)
                #writing them in the CSV file
            line_datas = [pr[3],"CVE", "PD", cve_date, cve_hour]
            write_datas(result_file_path, line_datas)
            
            for commit in commits:
                
                #looking for each "lessThan" commit dates (author + committer)
                author_date, author_hour = get_author_date_from_commit(linux_repo, commit)
                committer_date, committer_hour = get_committer_date_from_commit(linux_repo, commit)
                release_date, release_hour = get_release_date_from_commit(linux_repo, commit, semvers)
                
                #writing author date in CSV file
                line_datas = [pr[3], commit, "AD", author_date, author_hour]
                write_datas(result_file_path, line_datas)
                
                #writing committer date in CSV file
                line_datas = [pr[3], commit, "CD", committer_date, committer_hour]
                write_datas(result_file_path, line_datas)
                
                #writing release date in CSV file
                line_datas = [pr[3], commit, "RD", release_date, release_hour]
                write_datas(result_file_path, line_datas)
                
                del author_date, author_hour, committer_date, committer_hour
    print("Results writed")
    
def get_release_date_from_commit(repository, commit, semvers):
    commit_tag = get_commit_tag(repository, commit)
    semver = find_recentest_semver(semvers, commit_tag)
    v_semver = f"v{semver}"
    if semver:
        commit_hash = get_commit_hash_from_semver(repository, v_semver)
        release_date, release_hour = get_committer_date_from_commit(repository, commit_hash)
    else:
        release_date, release_hour = "Unknown", "Unknown"
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
    if recent_semvers:        
        closest_semver = recent_semvers[0]
        for semver in recent_semvers:
            if cmp_version(semver, closest_semver) == -1:
                closest_semver = semver
                
        return closest_semver
    else:
        return

def get_commit_hash_from_semver(repository, semver):
    repo = Repo(repository)
    commit_hash = repo.git.rev_parse(semver)
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

def write_datas(path, datas):
    with open(path, 'a', newline='') as csvfile:
        date_writer = csv.writer(csvfile, delimiter = ',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
        date_writer.writerow(datas)
    

def create_commit_patch_db(db, product, vendor):
    patch_directory = Path.cwd()/"CVE_patchs"
    patch_directory.mkdir(exist_ok=True)
    
    print("Creating database...")
    for pr in db:
        commits = []
        
        if pr[0].lower() == product:
            
            cve_patch_directory_json = Path(patch_directory/(pr[3].strip('.json'))/"JSON")
            cve_patch_directory_txt = Path(patch_directory/(pr[3].strip('.json'))/"TXT")
            cve_patch_directory_json.mkdir(parents = True, exist_ok=True)
            cve_patch_directory_txt.mkdir(parents = True, exist_ok=True)
            
            if product == "linux":
                for x in pr[1] : 
                    if "versions" in x: 
                        for y in x["versions"] :
                            if "versionType" in y:
                                if y["versionType"] == "git":
                                    if "lessThan" in y: 
                                        commits.append(y["lessThan"])
                
                for commit in commits:
                    files = get_modified_file(linux_repo, commit).split("\n")
                    parent_commit = get_parent_commit(linux_repo, commit)

                    for file in files:
                        commit_file_diff_json = cve_patch_directory_json/f"D_{file.replace("/",":")}_{commit}.json"
                        commit_file_diff_txt = cve_patch_directory_txt/f"D_{file.replace("/",":")}_{commit}.txt"
                        
                        commit_file_bug_json = cve_patch_directory_json/f"V_{file.replace("/",":")}_{commit}.json"
                        commit_file_bug_txt = cve_patch_directory_txt/f"V_{file.replace("/",":")}_{commit}.txt"
                        
                        commit_file_fixed_json = cve_patch_directory_json/f"NV_{file.replace("/",":")}_{commit}.json"
                        commit_file_fixed_txt = cve_patch_directory_txt/f"NV_{file.replace("/",":")}_{commit}.txt"
                        
                        diff = load_patch(linux_repo, commit, file)
                        if commit_file_diff_json.exists() or commit_file_diff_txt.exists():
                            commit_file_diff_json.unlink()
                            commit_file_diff_json.touch()
                            write_patch_json(commit_file_diff_json, diff)
                            commit_file_diff_txt.unlink()
                            commit_file_diff_txt.touch()
                            write_patch_txt(commit_file_diff_txt, diff) 
                        else :
                            commit_file_diff_json.touch()
                            write_patch_json(commit_file_diff_json, diff)
                            commit_file_diff_txt.touch()
                            write_patch_txt(commit_file_diff_txt, diff)
                        
                        datas = get_file_content(linux_repo, parent_commit, file)
                        if commit_file_bug_json.exists() or commit_file_bug_txt.exists():
                            commit_file_bug_json.unlink()
                            commit_file_bug_json.touch()
                            write_patch_json(commit_file_bug_json, datas)
                            commit_file_bug_txt.unlink()
                            commit_file_bug_txt.touch()
                            write_patch_txt(commit_file_bug_txt, datas) 
                        else :
                            commit_file_bug_json.touch()
                            write_patch_json(commit_file_bug_json, datas)
                            commit_file_bug_txt.touch()
                            write_patch_txt(commit_file_bug_txt, datas)
                        
                        datas = get_file_content(linux_repo, commit, file)
                        if commit_file_fixed_json.exists() or commit_file_fixed_txt.exists():
                            commit_file_fixed_json.unlink()
                            commit_file_fixed_json.touch()
                            write_patch_json(commit_file_fixed_json, datas)
                            commit_file_fixed_txt.unlink()
                            commit_file_fixed_txt.touch()
                            write_patch_txt(commit_file_fixed_txt, datas) 
                        else :
                            commit_file_fixed_json.touch()
                            write_patch_json(commit_file_fixed_json, datas)
                            commit_file_fixed_txt.touch()
                            write_patch_txt(commit_file_fixed_txt, datas)
                    

                    
            elif product == "zulip":
                for x in pr[1]:
                    if "versions" in x:
                        for y in x["versions"]:
                            commit_parent, commit_child = parse_zulip_version(zulip_repo,y["version"])
                            
                            cve_file_json = cve_patch_directory_json/f"{pr[3].strip('.json')}.json"
                            cve_file_txt = cve_patch_directory_txt/f"{pr[3].strip('.json')}.txt"
                 
                            patch = load_patch_zulip(zulip_repo, commit_parent, commit_child)
                            
                            if cve_file_json.exists() or cve_file_txt.exists():
                                cve_file_json.unlink()
                                cve_file_json.touch()
                                write_patch_json(cve_file_json, patch)
                                cve_file_txt.unlink()
                                cve_file_txt.touch()
                                write_patch_txt(cve_file_txt, patch) 
                            else :
                                cve_file_json.touch()
                                write_patch_json(cve_file_json, patch)
                                cve_file_txt.touch()
                                write_patch_txt(cve_file_txt, patch)

    print("Database created")
def get_file_content(repository, commit_hash, file_name):
    repo = Repo(repository)
    file_content = repo.git.show(f"{commit_hash}:{file_name}")
    return file_content

def get_modified_file(repository, commit_hash):
    repo = Repo(repository)
    file = repo.git.show('--name-only','--pretty=format:', commit_hash)
    return file
    
    
def parse_zulip_version(repository, version):
    if "," in version:
        
        commit_child = re.sub(".*<*\\s", "", version)
        commit_child = get_commit_hash_from_semver(repository, commit_child)
        commit_parent = get_parent_commit(repository, commit_child)
         
        commit_parent = get_commit_hash_from_semver(repository, commit_parent)
        commit_child = get_commit_hash_from_semver(repository, commit_child)
        
        return commit_parent, commit_child
    else:
        if "<" in version:
            commit_child = re.sub("<*=*\\s", "", version)
            commit_child = get_commit_hash_from_semver(repository, commit_child)
            commit_parent = get_parent_commit(repository, commit_child)
            return commit_parent, commit_child
        else:
            commit_parent = re.sub("=\\s", "", version)
            commit_child = get_child_commit(repository, commit_parent)
            
            commit_parent = get_commit_hash_from_semver(repository, commit_parent)
            commit_child = get_commit_hash_from_semver(repository, commit_child)
            return commit_parent, commit_child

def get_child_commit(repository, commit_parent):
    repo = Repo(repository)
    tags_in_line = repo.git.tag()
    tags = tags_in_line.split("\n")
    for tag in tags:
        if cmp_version(tag, commit_parent) == 1:
            return tag
            
            
def get_parent_commit(repository, commit_child):
    repo = Repo(repository)
    commit_parent = repo.commit(commit_child).parents[0]
    return commit_parent
       
def load_patch_zulip(repository, commit_parent, commit_child):
    repo = Repo(repository)
    patch = repo.git.diff(commit_parent, commit_child)
    return patch
        
        
def load_patch(repository, commit_num, file):
    repo = Repo(repository)
    commit = repo.commit(commit_num)
    patch = repo.git.diff(commit.parents[0], commit_num, "--",file)
    return patch

def write_patch_json(file, patch):
    with open(file, "w") as f:
        json.dump(patch, f)

def write_patch_txt(file, patch):
    with open(file, "w") as f:
        f.writelines(patch)

# STATS MADE BEYOND THIS POINT

def check_cves_validity(db, products_object):
    for pr in db:
        if pr[0] != "n/a":
            if pr[0] not in products_object:
                products_object[pr[0]] = product(pr[0], pr[1])
            else :
                products_object[pr[0]].check_vendors(pr[1])
                products_object[pr[0]].entries_count += 1
        else :
            product.invalid_entries += 1        
        
def write_stats(products_object):
    stats_file_name = create_stats_file()
    lines_datas = ["product name", "entries count", "fiability rate"]
    write_datas(stats_file_name, lines_datas)
    for prod in products_object:
        lines_datas = [products_object[prod].name, products_object[prod].get_entries(), products_object[prod].get_fiability_rate()]   
        write_datas(stats_file_name, lines_datas)
        
def create_stats_file():
    path = Path.cwd()/"stats"
    date = datetime.today().strftime('%Y-%m-%d')
    stats_file_name = path/f"{date}_CVE_fiability.csv"
    
    path.mkdir(exist_ok=True)
    if stats_file_name.exists():
        stats_file_name.unlink()
        stats_file_name.touch()
        print(f"\"{stats_file_name.name}\" already exists : file replaced")
        return stats_file_name
    else :
        stats_file_name.touch()
        print(f"\"{stats_file_name.name}\" file created")
        return stats_file_name
