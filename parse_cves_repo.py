import json
import os
import re
import argparse
from pathlib import Path
from cvev5 import git_pull_repo, parse_cve_id_with_year, check_cves_validity, write_stats, parse_cves, create_folders, initialize, repos_path


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="CVE lookup in CVEV5 database for a given product"
    )
    parser.add_argument("-i", "--input-dir", help="Input directory", required=True)
    parser.add_argument("-q", "--projects-required-quantity", help="Number of projects", required=True)
    parser.add_argument("-y", "--minimal-year-wanted", help="Since when", default=None)

    args = parser.parse_args()

    input_dir = args.input_dir
    quantity = args.projects_required_quantity

    if args.minimal_year_wanted is not None:
        minimal_year_wanted = args.minimal_year_wanted
    else:
        minimal_year_wanted = str(0)
# input_dir = "/home/paul.montoussy@Digital-Grenoble.local/gittedbase/stage/repos/cvelistV5"   
# quantity = 50    
# minimal_year_wanted = str(0)
    products = []
    products_object = {}
    print("Initialisation...")
    initialize(repos_path)
    print("Initialized")

    print("Updating datas from distant repositories...")
    i = 0
    for repo in Path(repos_path).iterdir():
        i += 1
        print(f"Updating {repo.name}.....{i}/{len(list(Path(repos_path).iterdir()))}")
        try:
            git_pull_repo(repo)
        except:
            print("error")    
    print("Update done")

    print("Loading database...")
    for root, dirnames, filenames in os.walk(input_dir):
        for filename in filenames:
            year, number = parse_cve_id_with_year(filename, minimal_year_wanted)
            if filename.endswith((".json")) and year is not None:
                # add errors='ignore' to skip a decoding error
                with open(os.path.join(root, filename)) as f:
                    data = json.load(f)
                    try:
                        if "containers" in data:
                            if "cna" in data["containers"]:
                                if "affected" in data["containers"]["cna"]:
                                    # print (data['containers']['cna']['affected'][0])
                                    x = data["containers"]["cna"]["affected"]
                                    urls = data["containers"]["cna"]["references"]
                                    date = data["cveMetadata"]["datePublished"]
                                    products.append(
                                        (x[0]["product"].lower(), x[0]["vendor"].lower(), urls, filename, date)
                                    )
                                        
                    except KeyError:
                        pass
                    except TypeError:
                        pass
                    
    print("Database loaded")

    products_count = len(products) 
        
    print("Product count: " + str(products_count))

    check_cves_validity(products, products_object)
    parse_cves(products, products_object)


    create_folders(products_object, quantity)

    products_object_sorted = dict(sorted(products_object.items(), key=lambda item : item[1].get_entries(), reverse=True))

    write_stats(products_object_sorted)
    