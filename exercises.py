import requests as re
from bs4 import BeautifulSoup
import os

URL = "https://www.kaggle.com"
response = re.get(URL)

print("response-->",response, "\ntype -->", type(response))
print("text -->", response.text, "\ncontent --> ", response.content, "\n status_code --> ", response.status_code)

#500 --> internal servr error

if response.status_code != 200:
    print("HTTP Connetion is not successful! Try again")
else:
    print("HTTP Connection is successfull")

soup = BeautifulSoup(response.content, "html.parser")

print("title with tags -->", soup.title,"\ntitle without tags -->", soup.title.text)

for link in soup.find_all("link"):
    print(link.get("href"))
print(soup.get_text())

#CREATE A FOLDER TO SAVE HTML FILES
folder = "mini_dataset"

if not os.path.exists(folder):
    os.mkdir(folder)

#2 DEFINE A FUNCTION THAT SCRAPES AND RETURNS IT

def scrape_content(URL):
    response = re.get(URL)
    if response.status_code == 200:
        print("HTTP connection is succussful! for the URL :", URL)
    else:
        print("HTTP connection is NOT successful! for the URL:", URL)
        return None

#3 DEFINE A FUNCTION TO SAVE A HTML FILE OF THE SCRAPED WEBPAGE IN A DIRECTORY

path = os.getcwd()+ "/" + folder

def save_html(to_where, text, name ):
    file_name = name + ".html"
    with open(os.path.join(to_where, file_name), "w") as f:
        f.write(text)

test_text = response.text
save_html(path, test_text,"example" )

# 4 DEFINE A URL LIST VARIABLE

URL_list= [
     "https://www.kaggle.com",
    "https://stackoverflow.com",
    "https://www.researchgate.net",
    "https://www.python.org",
    "https://www.w3schools.com",
    "https://wwwen.uni.lu",
    "https://github.com",
    "https://scholar.google.com",
    "https://www.mendeley.com",
    "https://www.overleaf.com"
]

#5 DEFINE A FUNCTION WHICH TAKES THE URL LIST and  RUN STEP 2 and  STEP 3 for EACH URL

def create_mini_dataset(to_where, URL_list):
    for i in range (0, len(URL_list)):
        content = scrape_content(URL_list[i])
        if content is not None:
            save_html(to_where, content.text,str(i))
        else:
            pass
    print("Mini dataset is created")

create_mini_dataset(path,URL_list)




