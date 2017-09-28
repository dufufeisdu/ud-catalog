import json
import string
import random

# seed json used functions


def getCatagory():
    with open('./static/publicSeed.json') as data_file:
        data = json.load(data_file)
        return map(lambda x: x["Name"], data["Category"])


def getItems():
    with open('./static/publicSeed.json') as data_file:
        data = json.load(data_file)
        return map(lambda x: x["Item"], data["Category"])


def getAllItems(arrs, cas):
    Items = []
    arrsLength = len(arrs)
    casLength = len(cas)
    for x in xrange(arrsLength):
        s = cas[x]
        for y in xrange(len(arrs[x])):
            Items.append([arrs[x][y]["Title"], s])
    return Items


def getCatagoryItems(casName):
    items = getItems()
    cat = getCatagory()
    items = getAllItems(items, cat)
    print(items)
    return filter(lambda x: x[1] == casName, items)


def getItemDescription(casName, title):
    categories = getCatagory()
    items = getItems()
    i = categories.index(casName)
    o = filter(lambda x: x["Title"] == title, items[i])
    return o[0]["Description"]


# print(getAllItems(getItems(), getCatagory()))
# print(getCatagoryItems("Basketball"))
# print(getItemDescription("Basketball", "Player"))

def getSeverState():
    return ''.join(
        random.choice(string.ascii_uppercase + string.digits) for x in range(32))


# User infor functions
