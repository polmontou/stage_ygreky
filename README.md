## Checks CVEs 

Both scripts (**parse_cves_repo.py** and **check_one_cvev58.py**) allow you to get some datas from CVEs.

- **check_one_cvev5.py** is made to parse 3 specifics products (you have to specify which one you want it to parse when you call the script) : Linux, Tensorflow and Zulip.
It creates a .csv file for each product where you'll find each CVE's dates and each commit corresponding to each CVE with author, committer and release date for each commit. It also creates a database contening 6 files per file modified by a commit : (3* .txt and 3* .json): 1x git diff (D), 1x vulnerable code (V), 1x patched code (NV). 
There's some specific arguments you can/have to pass to the script:
    - **-i** : **required** this is the input directory, you have to specify the path to CVE's local repo (you have to clone the CVE's repo: git@github.com:CVEProject/cvelistV5.git)
    - **-p** : **required** the product you want to parse (so Linux, Tensorflow or Zulip)
    - **-v** : *optionnal* you can specify which vendor you want
    - **-y** : *optionnal* you can specify since which year you want to parse CVE's (doesn't for Tensorflow, it automatically begins in 2018)

    For this script, you have to clone Linux, Tensorflow and Zulip repos :
        - [Linux](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git)
        - [Tensorflow](https://github.com/tensorflow/tensorflow.git)
        - [Zulip](https://github.com/zulip/zulip.git)

    <u>ex :<u> python3 check_one_cvev5.py -i <input_dir> -p linux -y 2025
  
- **parse_cves_repo.py** is made to parse all CVE's entries, seek for a specific pattern in each CVE to see if it can fetch datas from distant repos, if it's the case, it clones distant repo and creates a folder per poduct in which we will have the same datas than in the precedent script (except release date of each commit). 
Here, you hace to specify :
    - **-i** : **required** this is the input directory, you have to specify the path to CVE's local repo (you have to clone the CVE's repo: git@github.com:CVEProject/cvelistV5.git)
    - **-q**: **required** you specify the number of products you want to parse (that's not the number of products you'll have in output because sometimes datas are unreachable even if we have the distant repo)

    <u>ex :<u> python3 parse_cves_repo.py -i <input_dir> -q 30
  
# You have to :

- Download the **cmp_version** library with :
    ```pip install cmp_version```
    
- Modify pathes in **cvev5.py**, at the beginnig of the script in *repos_path* (where you want the 2nd script to clone all the repos to parse CVE) and *repos* (linux, tensorflow, cves, zulip) 
