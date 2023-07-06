import requests
import multiprocessing
from os import path
from bs4 import BeautifulSoup

url = "https://wiki.ubuntu.com/Releases"
index_url = "http://my.archive.ubuntu.com/ubuntu/indices/"
repos = ["main", "restricted", "universe", "multiverse"]
repos_no = ["src", "debian-installer"]
ubuntu_version_lookup = {}
len(ubuntu_version_lookup)


def get_ubuntu_versions():
    req = requests.get(url)
    soup = BeautifulSoup(req.content, "html.parser")

    version_table = {}

    table = soup.find("h3", id = "Current").find_next("table").find("tr").find_all_next("tr")
    for ver in table:
        try:
            ver_num = ver.find("p", class_ = "line862").text
            ver_name = ver.find("a").text
            #print(tuple(ver_num, ver_name))
            version_table[ver_num] = ver_name
            #print(ver_num + "\t" + ver_name)
            """ print("\n\n\n") """
        except:
            pass

    return version_table
    

for num, name in ubuntu_version_lookup:
    print(num + "\t" + name)
    #print(item)

def task(index):
    packages = set()
    packs = requests.get(index_url + index).text.splitlines()
    for line in packs:
            packages.add(line.split()[0])
    return packages

def get_packages_by_version(ver):

    global ubuntu_version_lookup
    if len(ubuntu_version_lookup) == 0:
        ubuntu_version_lookup = get_ubuntu_versions()
    ver_name = ubuntu_version_lookup[ver].lower().split()[0] if ver in ubuntu_version_lookup else None

    if not ver_name == None:
        package_list = set()

        if not path.isfile(ver_name):
            package_index = []
            soup = BeautifulSoup(requests.get(index_url).content, "html.parser")
            indices = soup.find("table").find(string="Parent Directory").find_all_next("a")
            for index in indices:
                separated_text = index.text.split('.')
                package_index.append(index.text) if ver_name in separated_text and filter(lambda x: x in separated_text[2], repos) and len(list(filter(lambda x: x in separated_text, repos_no))) == 0 else None

            with multiprocessing.Pool() as mp:
                packages = mp.map(task, package_index)

            package_list = package_list.union(*packages)

            with open(ver_name, 'w') as f:
                        for package in package_list:
                            f.write(package + "\n")

        else:
            with open(ver_name, 'r') as f:
                for package in f.readlines():
                    package_list.add(package.strip())

        print(len(package_list))

        return list(package_list)
    
def find_package(os_ver, package_name):
    package_list = []
    for pack in get_packages_by_version(os_ver):
        if package_name in pack:
            package_list.append(pack)
    return package_list


""" print(get_packages_by_version("Ubuntu 23.04")) """