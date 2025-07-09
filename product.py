class product:
    invalid_entries = 0

    
    def __init__(self, name: str, vendor: str = "n/a"):
        self.name = name
        self.entries_count = 1
        self.valid_entries_count = 0
        self.check_vendors(vendor)
        self.commit_url = 0
        self.urls = []
        self.cves = {}
               
    def check_vendors(self, vendor):
        if vendor != "n/a":
            self.valid_entries_count += 1
        else:
            product.invalid_entries +=1
    
    def get_entries(self):
        return self.entries_count
    
    def get_valid_entries(self):
        return self.valid_entries_count
    
    def get_fiability_rate(self):
        rate = (self.valid_entries_count/self.entries_count)
        return rate 
    