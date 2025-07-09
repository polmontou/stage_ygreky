# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: Copyright 2024 Marta Rybczynska
# $ git init 
import shutil
import json
import re
import csv
from pathlib import Path
from datetime import datetime
from dateutil.parser import parse
from dateutil.tz import UTC
from git import Repo, GitCommandError, GitError
from cmp_version import cmp_version
from product import product

repos_path = "/home/paul.montoussy@Digital-Grenoble.local/gittedbase/stage/repos"
repos = { 
    "cvelistV5" : f"{repos_path}/cvelistV5",
    "linux" : f"{repos_path}/linux",
    "zulip" : f"{repos_path}/zulip",
    "tensorflow" : f"{repos_path}/tensorflow"
}
distant_repos = {
    "cvelistV5" : "https://github.com/CVEProject/cvelistV5.git",
    "linux" : "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git",
    "zulip" : "https://github.com/zulip/zulip.git",
    "tensorflow" : "https://github.com/tensorflow/tensorflow.git"
}

def initialize(repos_path):
    repos_path = Path(repos_path)
    repos_path.mkdir(exist_ok=True, parents=True)
    for repo in repos:
        project_path = Path(repos[repo])
        if not project_path.exists():
           print(f"{repo} getting cloned")
           Repo.clone_from(distant_repos[repo], project_path)
           
    
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

def get_dates(db, product, year):

    result_file_path = create_result_file(product, year if product != "tensorflow" else "2018")
    print("Writing results...")
    for pr in db:       
        line_datas = []
        commits = []
        semvers = []
          
        if pr[0].lower() == product:
            
            if product == "linux":
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
                
            elif product == "zulip":
                commits = get_commit_hash_from_zuliprepo(str(pr[2]))
                commits = list(set(commits))

                if len(commits) == 0:
                    for x in pr[1]:
                        if "versions" in x:
                            for y in x["versions"]:
                                try:
                                    commit_parent, commit = parse_zulip_version(repos[product],y["version"])
                                    commit_semver = get_commit_tag(repos[product], commit)
                                    child_semver = get_child_commit(repos[product], commit_semver)
                                    child_commit = get_commit_hash_from_tag(repos[product], child_semver)
                                    commits.append(child_commit)
                                except:
                                    pass
            # looking for CVE publication date
            cve_date, cve_hour = get_publication_date_from_CVE(pr[2])
                #writing them in the CSV file
            line_datas = [pr[3],"CVE", "PD", cve_date, cve_hour]
            write_datas(result_file_path, line_datas)
            
            for commit in commits:
                #looking for each "lessThan" commit dates (author + committer)
                author_date, author_hour = get_author_date_from_commit(repos[product], commit)
                committer_date, committer_hour = get_committer_date_from_commit(repos[product], commit)
                
                if product != "zulip":
                    release_date, release_hour = get_release_date_from_commit(repos[product], commit, semvers)
                else:
                    commit_semver = get_commit_tag(repos[product], commit)
                    child_semver = get_child_commit(repos[product], commit_semver)
                    if not child_semver :
                        release_date, release_hour = "Not found", "Not found"
                    else:    
                        child_commit = get_commit_hash_from_tag(repos[product], child_semver)
                        release_date, release_hour = get_committer_date_from_commit(repos[product], child_commit)
                
                #writing author date in CSV file
                line_datas = [pr[3], commit, "AD", author_date, author_hour]
                write_datas(result_file_path, line_datas)
                
                #writing committer date in CSV file
                line_datas = [pr[3], commit, "CD", committer_date, committer_hour]
                write_datas(result_file_path, line_datas)
                
                #writing release date in CSV file
                line_datas = [pr[3], commit, "RD", release_date, release_hour]
                write_datas(result_file_path, line_datas)
                
                del author_date, author_hour, committer_date, committer_hour, release_date, release_hour
                    
    print("Results writed")
    
def get_commit_tag(repository, commit_num):
    repo=Repo(repository)
    commit_tag = repo.git.describe('--tags', commit_num)
    return clean_commit_tag(commit_tag)

def get_commit_hash_from_zuliprepo(cve_content):
    pattern = r"https://github\.com/zulip/zulip/commit/(\w*)"
    match = re.findall(pattern, cve_content)
    return match
        
def get_tensorflow_cve_dates():
    result_file_path = create_result_file("tensorflow", "2018")
    print("Writing results...")
    
    tf_repo = Path(repos["tensorflow"])
    tf_cve_repo = tf_repo.joinpath("tensorflow","security","advisory")
    
    for file in tf_cve_repo.iterdir():
        cve_id = get_cveid_from_tfrepo(file)
        commit_list = get_commit_hash_from_tfrepo(file)

        cve_year = re.sub("CVE-", "", cve_id)
        cve_year = re.sub(r"-\d*", "", cve_year)
        
        cve_nr = re.sub(r"CVE-\d{4}-", "", cve_id)
        cve_nr = re.sub(r"\d{3}$", "xxx", cve_nr)
        
        cve_file = f"{cve_id}.json"
        cves_repo_path = Path(repos["cvelistV5"])
        cves_repo_path = cves_repo_path.joinpath("cves", cve_year, cve_nr, cve_file)
        
        with open(cves_repo_path, "r") as f:
            data = json.load(f)

            cve_date, cve_hour = get_publication_date_from_CVE(data)
            #writing them in the CSV file
            line_datas = [f"{cve_id}.json","CVE", "PD", cve_date, cve_hour]
            
            write_datas(result_file_path, line_datas)
            
            for commit in commit_list:
                if is_hexadecimal(commit): 
                    repo = Repo(repos["tensorflow"])
                    tags = repo.git.tag("--contains", commit).split("\n")
                    smallest_tag = tags[0]
                    for tag in tags:
                        if cmp_version(tag, smallest_tag) == -1:
                            smallest_tag = tag   
                    child_commit = get_commit_hash_from_tag(repos["tensorflow"], smallest_tag)

                    #looking for each "lessThan" commit dates (author + committer)
                    author_date, author_hour = get_author_date_from_commit(repos["tensorflow"], commit)
                    committer_date, committer_hour = get_committer_date_from_commit(repos["tensorflow"], commit)
                    release_date, release_hour = get_committer_date_from_commit(repos["tensorflow"], child_commit)
                   
                    #writing author date in CSV file
                    line_datas = [cve_file, commit, "AD", author_date, author_hour]
                    write_datas(result_file_path, line_datas)
                    
                    #writing committer date in CSV file
                    line_datas = [cve_file, commit, "CD", committer_date, committer_hour]
                    write_datas(result_file_path, line_datas)
                    
                    #writing release date in CSV file
                    line_datas = [cve_file, commit, "RD", release_date, release_hour]
                    write_datas(result_file_path, line_datas)
                    
                    del author_date, author_hour, committer_date, committer_hour, release_date, release_hour                       
                    
def get_year_from_cve(cve_id):
    pattern = r"CVE-(\d{4})-(\d+)\.json"
    match = re.match(pattern, cve_id)
    if match:
        cve_year = match.group(1)
        return cve_year

def get_release_date_from_commit(repository, commit, semvers):
    commit_tag = get_commit_tag(repository, commit)
    semver = find_recentest_semver(semvers, commit_tag)
    if repository != repos["zulip"]:
        v_semver = f"v{semver}"
    else:
        v_semver = semver
        
    if semver:
        commit_hash = get_commit_hash_from_tag(repository, v_semver)
        release_date, release_hour = get_committer_date_from_commit(repository, commit_hash)
    else:
        release_date, release_hour = "Unknown", "Unknown"
    return release_date, release_hour
    
def get_commit_tag(repository, commit_num):
    repo=Repo(repository)
    commit_tag = repo.git.describe('--tags', commit_num)
    return clean_commit_tag(commit_tag)
    
def clean_commit_tag(commit_tag):
    clean_commit_tag = re.sub(r"\s[a-zA-Z]\s", "", commit_tag)
    clean_commit_tag = re.sub(r"\s-.*\s","", clean_commit_tag)
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

def get_commit_hash_from_tag(repository, tag):
    repo = Repo(repository)
    tag = re.sub(r"[a-zA-Z]", "", tag)
    tag = re.sub(" ", "",tag)
    tag = re.sub(r"-.*","", tag)
    commit_hash = repo.git.rev_parse(tag)
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
    cve_date, cve_hour = parse_date(pr["cveMetadata"]["datePublished"])
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
    patch_directory = Path.cwd()/f"CVE_patchs_{product}"
    patch_directory.mkdir(exist_ok=True)
    
    print("Creating database...")
    if product != "tensorflow":    
        for pr in db:
            commits = []
            
            if pr[0].lower() == product:
                
                if product == "linux":
                    cve_patch_directory_json = Path(patch_directory/(pr[3].strip('.json'))/"JSON")
                    cve_patch_directory_txt = Path(patch_directory/(pr[3].strip('.json'))/"TXT")
                    cve_patch_directory_json.mkdir(parents = True, exist_ok=True)
                    cve_patch_directory_txt.mkdir(parents = True, exist_ok=True)
                    for x in pr[1] : 
                        if "versions" in x: 
                            for y in x["versions"] :
                                if "versionType" in y:
                                    if y["versionType"] == "git":
                                        if "lessThan" in y: 
                                            commits.append(y["lessThan"])
                    
                    for commit in commits:
                        files = get_modified_file(repos[product], commit).split("\n")
                        parent_commit = get_parent_commit(repos[product], commit)
                        
                        metadata_commit_file_json = cve_patch_directory_json/(f"{pr[3]}_MD_{commit}.json")
                        metadata_commit_file_txt = cve_patch_directory_txt/(f"{pr[3]}_MD_{commit}.txt")
                        
                        metadatas = get_commits_metadatas(repos[product], commit)
                        if metadata_commit_file_json.exists() or metadata_commit_file_txt.exists():
                            metadata_commit_file_json.unlink()
                            metadata_commit_file_json.touch()
                            write_patch_json(metadata_commit_file_json, metadatas)
                            metadata_commit_file_txt.unlink()
                            metadata_commit_file_txt.touch()
                            write_patch_txt(metadata_commit_file_txt, metadatas) 
                        else :
                            metadata_commit_file_json.touch()
                            write_patch_json(metadata_commit_file_json, metadatas)
                            metadata_commit_file_txt.touch()
                            write_patch_txt(metadata_commit_file_txt, metadatas)

                        for file in files:
                            commit_file_diff_json = cve_patch_directory_json/f"{pr[3]}_D_{file.replace("/",":")}_{commit}.json"
                            commit_file_diff_txt = cve_patch_directory_txt/f"{pr[3]}_D_{file.replace("/",":")}_{commit}.txt"
                            
                            commit_file_bug_json = cve_patch_directory_json/f"{pr[3]}_V_{file.replace("/",":")}_{commit}.json"
                            commit_file_bug_txt = cve_patch_directory_txt/f"{pr[3]}_V_{file.replace("/",":")}_{commit}.txt"
                            
                            commit_file_fixed_json = cve_patch_directory_json/f"{pr[3]}_NV_{file.replace("/",":")}_{commit}.json"
                            commit_file_fixed_txt = cve_patch_directory_txt/f"{pr[3]}_NV_{file.replace("/",":")}_{commit}.txt"
                            
                            diff = load_patch(repos[product], commit, file)
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
                            
                            datas = get_file_content(repos[product], parent_commit, file)
                            if datas == None:
                                datas = f"File created by {commit} commit."
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
                            
                            datas = get_file_content(repos[product], commit, file)
                            if datas == None:
                                datas = f"File deleted by {commit} commit."
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
                    cve_patch_directory_json = Path(patch_directory/(pr[3].strip('.json'))/"JSON")
                    cve_patch_directory_txt = Path(patch_directory/(pr[3].strip('.json'))/"TXT")
                    cve_patch_directory_json.mkdir(parents = True, exist_ok=True)
                    cve_patch_directory_txt.mkdir(parents = True, exist_ok=True)
                    for x in pr[1]:
                        if "versions" in x:
                            for y in x["versions"]:
                                commit_parent, commit_child = parse_zulip_version(repos[product],y["version"])
                                if commit_child != None :
                                    files = get_modified_file(repos[product], commit_child).split("\n")
                                    
                                    metadata_commit_file_json = cve_patch_directory_json/(f"{pr[3]}_MD_{commit_parent}.json")
                                    metadata_commit_file_txt = cve_patch_directory_txt/(f"{pr[3]}_MD_{commit_parent}.txt")
                                    
                                    metadatas = get_commits_metadatas(repos[product], commit_parent)
                                    if metadata_commit_file_json.exists() or metadata_commit_file_txt.exists():
                                        metadata_commit_file_json.unlink()
                                        metadata_commit_file_json.touch()
                                        write_patch_json(metadata_commit_file_json, metadatas)
                                        metadata_commit_file_txt.unlink()
                                        metadata_commit_file_txt.touch()
                                        write_patch_txt(metadata_commit_file_txt, metadatas) 
                                    else :
                                        metadata_commit_file_json.touch()
                                        write_patch_json(metadata_commit_file_json, metadatas)
                                        metadata_commit_file_txt.touch()
                                        write_patch_txt(metadata_commit_file_txt, metadatas)

                                    for file in files:
            
                                        commit_file_diff_json = cve_patch_directory_json/f"{pr[3]}_D_{file.replace("/",":")}_{commit_child}.json"
                                        commit_file_diff_txt = cve_patch_directory_txt/f"{pr[3]}_D_{file.replace("/",":")}_{commit_child}.txt"
                                        
                                        commit_file_bug_json = cve_patch_directory_json/f"{pr[3]}_V_{file.replace("/",":")}_{commit_child}.json"
                                        commit_file_bug_txt = cve_patch_directory_txt/f"{pr[3]}_V_{file.replace("/",":")}_{commit_child}.txt"
                                        
                                        commit_file_fixed_json = cve_patch_directory_json/f"{pr[3]}_NV_{file.replace("/",":")}_{commit_child}.json"
                                        commit_file_fixed_txt = cve_patch_directory_txt/f"{pr[3]}_NV_{file.replace("/",":")}_{commit_child}.txt"
                                        
                                        patch = load_patch(repos[product], commit_child, file)    
                                        if commit_file_diff_json.exists() or commit_file_diff_txt.exists():
                                            commit_file_diff_json.unlink()
                                            commit_file_diff_json.touch()
                                            write_patch_json(commit_file_diff_json, patch)
                                            commit_file_diff_txt.unlink()
                                            commit_file_diff_txt.touch()
                                            write_patch_txt(commit_file_diff_txt, patch) 
                                        else :
                                            commit_file_diff_json.touch()
                                            write_patch_json(commit_file_diff_json, patch)
                                            commit_file_diff_txt.touch()
                                            write_patch_txt(commit_file_diff_txt, patch)
                                        
                                        datas = get_file_content(repos[product], commit_parent, file)
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
                                        
                                        datas = get_file_content(repos[product], commit_child, file)
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
    else:
                
        tf_repo = Path(repos["tensorflow"])
        tf_cve_repo = tf_repo.joinpath("tensorflow","security","advisory")
        for file in tf_cve_repo.iterdir():
            cve_id = get_cveid_from_tfrepo(file)
            commit_list = get_commit_hash_from_tfrepo(file)
            
            cve_patch_directory_json = Path(patch_directory/cve_id/"JSON")
            cve_patch_directory_txt = Path(patch_directory/cve_id/"TXT")
            cve_patch_directory_json.mkdir(parents = True, exist_ok=True)
            cve_patch_directory_txt.mkdir(parents = True, exist_ok=True)
            
            
            for commit in commit_list:
                if is_hexadecimal(commit):
                    files = get_modified_file(repos["tensorflow"], commit).split("\n")
                    parent_commit = get_parent_commit(repos["tensorflow"], commit)
                    metadata_commit_file_json = cve_patch_directory_json/(f"{cve_id}_MD_{commit}.json")
                    metadata_commit_file_txt = cve_patch_directory_txt/(f"{cve_id}_MD_{commit}.txt")
                    
                    metadatas = get_commits_metadatas(repos[product], commit)
                    if metadata_commit_file_json.exists() or metadata_commit_file_txt.exists():
                        metadata_commit_file_json.unlink()
                        metadata_commit_file_json.touch()
                        write_patch_json(metadata_commit_file_json, metadatas)
                        metadata_commit_file_txt.unlink()
                        metadata_commit_file_txt.touch()
                        write_patch_txt(metadata_commit_file_txt, metadatas) 
                    else :
                        metadata_commit_file_json.touch()
                        write_patch_json(metadata_commit_file_json, metadatas)
                        metadata_commit_file_txt.touch()
                        write_patch_txt(metadata_commit_file_txt, metadatas)
                        
                    for file in files:
                        
                        pattern = r"testdata"
                        match = re.search(pattern, file)
                        
                        if match:
                            continue
                            
                        if not file.endswith(".bin"):
                            commit_file_diff_json = cve_patch_directory_json/f"{cve_id}_D_{file.replace("/",":")}_{commit}.json"
                            commit_file_diff_txt = cve_patch_directory_txt/f"{cve_id}_D_{file.replace("/",":")}_{commit}.txt"
                            
                            commit_file_bug_json = cve_patch_directory_json/f"{cve_id}_V_{file.replace("/",":")}_{commit}.json"
                            commit_file_bug_txt = cve_patch_directory_txt/f"{cve_id}_V_{file.replace("/",":")}_{commit}.txt"
                            
                            commit_file_fixed_json = cve_patch_directory_json/f"{cve_id}_NV_{file.replace("/",":")}_{commit}.json"
                            commit_file_fixed_txt = cve_patch_directory_txt/f"{cve_id}_NV_{file.replace("/",":")}_{commit}.txt"
                            
                            diff = load_patch(repos["tensorflow"], commit, file)
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
                            
                            datas = get_file_content(repos["tensorflow"], parent_commit, file)
                            if datas == None:
                                datas = f"File created by {commit} commit."
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
                        
                            datas = get_file_content(repos["tensorflow"], commit, file)
                            if datas == None:
                                datas = f"File deleted by {commit} commit."
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

    print("Database created")
    
def get_commit_hash_from_tfrepo(file):
    with open(file, "r") as f:
        content = f.read()
        pattern = r"https://github\.com/tensorflow/tensorflow/commit/(\w*)"
        match = re.findall(pattern, content)
        return match

    
def get_cveid_from_tfrepo(file):
    with open(file, "r") as f:
        content = f.read()
        pattern = r"CVE-(\d{4})-(\d+)"
        match = re.search(pattern, content)
        cve_id = match.group()
        if match :
            return cve_id
   
def get_file_content(repository, commit_hash, file_name):
    repo = Repo(repository)
    try:
        file_content = repo.git.show(f"{commit_hash}:{file_name}")
    except:
        return None
    return file_content

def get_modified_file(repository, commit_hash):
    repo = Repo(repository)
    file = repo.git.show('--name-only','--pretty=format:', commit_hash)
    if file[0] != "" :
        return file
    return None
    
    
def parse_zulip_version(repository, version):
    if "," in version:
        commit_child = re.sub(".*<*\\s", "", version)
        if not is_hexadecimal(commit_child):
            commit_child = get_commit_hash_from_tag(repository, commit_child)
        commit_parent = get_parent_commit(repository, commit_child)
        
        return commit_parent, commit_child
    else:
        if "<" in version:
            commit_child = re.sub("<*=*\\s", "", version)
            if not is_hexadecimal(commit_child):
                commit_child = get_commit_hash_from_tag(repository, commit_child)
            commit_parent = get_parent_commit(repository, commit_child)
            return commit_parent, commit_child
        else:
            commit_parent = re.sub("=\\s", "", version)
            commit_child = get_child_commit(repository, commit_parent)
            if commit_child != None :
                commit_parent = get_commit_hash_from_tag(repository, commit_parent)       
                commit_child = get_commit_hash_from_tag(repository, commit_child)
                return commit_parent, commit_child
            else:
                return commit_parent, None

def get_child_commit(repository, commit_parent):
    repo = Repo(repository)
    try:
        tags = repo.git.tag("--contains", commit_parent).split("\n")
        recent_semvers = []
        for tag in tags:
            tag = re.sub(r"^\D*", "", tag)
            tag = re.sub(r"[\-a-z].*$", "", tag)
            if cmp_version(tag, commit_parent) == 1:
                recent_semvers.append(tag)
        if not recent_semvers:
            return None
        smallest_one = recent_semvers[0]
        for semver in recent_semvers:
            if cmp_version(semver, smallest_one) == -1:
                smallest_one = semver
        return smallest_one
    except:
        return None
        
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
                   
def parse_cves(db, products_object):
    for pr in db:
        if pr[0] == "n/a":
            pr = list(pr)
            pr[0] = find_project_name(pr[2])
        if pr[0] != None:
            if pr[0] not in products_object:
                    products_object[pr[0]] = product(pr[0], pr[1])
            else :
                products_object[pr[0]].check_vendors(pr[1])
                products_object[pr[0]].entries_count += 1
        
            products_object[pr[0]].cves[pr[3]] = {"publication_date" : pr[4]}
                 
    count_urls(db, products_object)
    # create_folders(products_object)
    
def find_project_name(urls):         
    pattern = r"https://github\.com/\w*/(\w*)/commit/\w*"
    match = re.match(pattern, str(urls))
    if match:
        match = match.group(1)
        return match   
    return None
        
def count_urls(db, products_object):
    for pr in db:  
        if pr[0] == "n/a":
            pr = list(pr)
            pr[0] = find_project_name(pr[2])
        if pr[0] != None:      
            pattern = r"https://github\.com/\w*/\w*/commit/\w*"
            match = re.findall(pattern, str(pr[2]))
            match = list(set(match))
            products_object[pr[0]].commit_url += len(match)
            if match:
                products_object[pr[0]].urls = match
                products_object[pr[0]].cves[pr[3]]["urls"] = match
 
                      
def create_folders(products_object, quantity):
    i = 0
    for prod in products_object: 
            if products_object[prod].commit_url > 0 and i < int(quantity):
                i += 1  
                path = Path.cwd().joinpath("resultats", products_object[prod].name.replace("/", ":"))
                path.mkdir(parents = True, exist_ok = True)
                print(f"Cloning and parsing {prod}.....{i}/{quantity}")
                clone_repo(products_object[prod])
                find_dates_and_datas(products_object[prod])
                print(f"{prod} cloned and parsed")
              

                
def find_dates_and_datas(product: product):
    date = datetime.today().strftime('%Y-%m-%d')
    result_repo_path = Path.cwd().joinpath("resultats", product.name.replace("/", ":"))
    datas_file_path = result_repo_path.joinpath("patch")
    result_file_path = result_repo_path.joinpath(f"{date}_{product.name.replace("/", ":")}_dates.csv")
 
    if result_file_path.exists():
        result_file_path.unlink()
    result_file_path.touch()
    
    
    pattern = r"https://github\.com/\w*/\w*/commit/(\w*)"
    
    i = 0
    
    for cve in product.cves:
        if "urls" in product.cves[cve]:
            try :
                # looking for CVE publication date
                cve_date, cve_hour = parse_date(product.cves[cve]["publication_date"])
                    # writing them in the CSV file
                line_datas = [cve,"CVE", "PD", cve_date, cve_hour, "-","-","-"]
                write_datas(result_file_path, line_datas)
                
                for url in product.cves[cve]["urls"]:
                    match = re.match(pattern, url)
                    commit = match.group(1)
                    if match: 
                        author_date, author_hour = get_author_date_from_commit(repos[product.name], commit)
                        committer_date, committer_hour = get_committer_date_from_commit(repos[product.name], commit)
                        
                        # writing dates in CSV file
                        line_datas = [cve, commit, "AD", author_date, author_hour, "CD", committer_date, committer_hour]
                        write_datas(result_file_path, line_datas)
                        del author_date, author_hour, committer_date, committer_hour
                        
                        i += 1
                        
                        files = get_modified_file(repos[product.name], commit).split("\n")                       
                        parent_commit = get_parent_commit(repos[product.name], commit)


                        if len(files) > 0:
                            
                            cve_patch_directory_json = datas_file_path.joinpath("JSON")
                            cve_patch_directory_txt = datas_file_path.joinpath("TXT")
                            Path(cve_patch_directory_json).mkdir(parents=True, exist_ok=True)
                            Path(cve_patch_directory_txt).mkdir(parents=True, exist_ok=True)
                            
                            metadata_commit_file_json = cve_patch_directory_json/(f"{cve}_MD_{commit}.json")
                            metadata_commit_file_txt = cve_patch_directory_txt/(f"{cve}_MD_{commit}.txt")
                            
                            metadatas = get_commits_metadatas(repos[product.name], commit)
                            if metadata_commit_file_json.exists() or metadata_commit_file_txt.exists():
                                metadata_commit_file_json.unlink()
                                metadata_commit_file_json.touch()
                                write_patch_json(metadata_commit_file_json, metadatas)
                                metadata_commit_file_txt.unlink()
                                metadata_commit_file_txt.touch()
                                write_patch_txt(metadata_commit_file_txt, metadatas) 
                                
                            else :
                                metadata_commit_file_json.touch()
                                write_patch_json(metadata_commit_file_json, metadatas)
                                metadata_commit_file_txt.touch()
                                write_patch_txt(metadata_commit_file_txt, metadatas)
                            
                            for file in files:
                                    if not file.endswith(".bin"):
                                        commit_file_diff_json = cve_patch_directory_json/f"{cve}_D_{file.replace("/",":")}_{commit}.json"
                                        commit_file_diff_txt = cve_patch_directory_txt/f"{cve}_D_{file.replace("/",":")}_{commit}.txt"
                                        
                                        commit_file_bug_json = cve_patch_directory_json/f"{cve}_V_{file.replace("/",":")}_{commit}.json"
                                        commit_file_bug_txt = cve_patch_directory_txt/f"{cve}_V_{file.replace("/",":")}_{commit}.txt"
                                        
                                        commit_file_fixed_json = cve_patch_directory_json/f"{cve}_NV_{file.replace("/",":")}_{commit}.json"
                                        commit_file_fixed_txt = cve_patch_directory_txt/f"{cve}_NV_{file.replace("/",":")}_{commit}.txt"

                                        diff = load_patch(repos[product.name], commit, file)
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
                                        
                                        datas = get_file_content(repos[product.name], parent_commit, file)
                                        if datas == None:
                                            datas = f"File created by {commit} commit."
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
                                    
                                        datas = get_file_content(repos[product.name], commit, file)
                                        if datas == None:
                                            datas = f"File deleted by {commit} commit."
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
                           
            except Exception as e:
                continue
            
    if i == 0 :
        result_file_path.unlink()
        result_repo_path.rmdir()
    elif len(list(cve_patch_directory_json.iterdir())) == 1 and len(list(cve_patch_directory_txt.iterdir())) == 1:
        current_path = Path.cwd().joinpath("resultats", product.name.replace("/", ":"))
        shutil.rmtree(current_path)
           
def get_commits_metadatas(repository, commit):
    repo = Repo(repository)
    metadatas = repo.git.show("-s", commit)
    return metadatas                      
                     
def clone_repo(product: product):
    pattern = r"https://github\.com/(\w*)/(\w*)/commit/\w*"
    match = re.match(pattern, product.urls[0])
    if match:
        name = match.group(1)
        project = match.group(2) 
           
    repo_path = Path(repos_path)
    project_repo = repo_path.joinpath(project)
    
    if not project_repo in repo_path.iterdir():
        git_url = f"https://null:null@github.com/{name}/{project}.git"
        try:
            print(f"{project} getting cloned")
            Repo.clone_from(git_url, project_repo)
        except GitCommandError or GitError :
            print("Repo unreachable")
    repos[project.lower()] = f"{project_repo}"

     
def write_stats(products_object):
    stats_file_name = create_stats_file()
    lines_datas = ["product name", "entries count", "fiability rate","commit url count"]
    write_datas(stats_file_name, lines_datas)
    for prod in products_object:
        lines_datas = [products_object[prod].name, products_object[prod].get_entries(), products_object[prod].get_fiability_rate(), products_object[prod].commit_url]   
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


def is_hexadecimal(num):
    try:
        int(num, 16)
        return True
    except ValueError:
        return False
    
# 