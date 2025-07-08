# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: Copyright 2024 Marta Rybczynska

import json
import os
import re
import argparse
from pathlib import Path
from cvev5 import parse_cve_id_with_year, get_dates, git_pull_repo, get_tensorflow_cve_dates, create_commit_patch_db, initialize, repos_path, repos

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="CVE lookup in CVEV5 database for a given product"
    )
    parser.add_argument("-i", "--input-dir", help="Input directory", required=True)
    parser.add_argument("-p", "--product", help="Product name", required=True)
    parser.add_argument("-e", "--vendor", help="Vendor name", default=None)
    parser.add_argument("-y", "--minimal-year-wanted", help="Since when", default=None)

    args = parser.parse_args()

    input_dir = args.input_dir
    
    product = args.product.lower()
    
    if args.vendor is not None:
        vendor = args.vendor.lower()
    else:
        vendor = "*"

    if args.minimal_year_wanted is not None and product != "tensorflow":
        minimal_year_wanted = args.minimal_year_wanted
    elif product == "tensorflow":
        minimal_year_wanted = "2018"
    else:
        minimal_year_wanted = "0"
        
    
        
    products = []

    print("Updating datas from distant repositories...")
    for repo in Path(repos_path).iterdir():
        print(repo)
        try:
            git_pull_repo(repo)
        except:
            print("error")    
    print("Update done")
    
    print("Loading database...")

    if product != "tensorflow": 
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
                                    if "affected" in data["containers"]["cna"] and product != "tensorflow":
                                        x = data["containers"]["cna"]["affected"]
                                        products.append(
                                            (x[0]["product"].lower(), x, data, filename)
                                        )
                                            

                        except KeyError:
                            pass
                        except TypeError:
                            pass
    
    
        products_sorted = sorted(products, key=lambda product: product[0])
        print("Product count: " + str(len(products)))
    
    
        get_dates(products, product, minimal_year_wanted)
    else :
        print("Database loaded")
        get_tensorflow_cve_dates()
    create_commit_patch_db(products, product, vendor)
