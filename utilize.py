import json
global categories, items

with open('./static/publicSeed.json') as data_file:
    data = json.load(data_file)
    categories = map(lambda x: x["Name"], data["Category"])
    items = map(lambda x: x["Item"], data["Category"])


def getAllItems(arrs, cas):
    Ites = []
    arrsLength = len(arrs)
    casLength = len(cas)
    for x in xrange(arrsLength):
        s = cas[x]
        for y in xrange(len(arrs[x])):
            Ites.append(arrs[x][y]["Title"] + "(" + s + ")")
    return Ites


def getCatagoryItems(casName):
    i = categories.index(casName)
    return map(lambda x: x["Title"], items[i])


def getItemDescription(casName, title):
    i = categories.index(casName)
    o = filter(lambda x: x["Title"] == title, items[i])
    return o[0]["Description"]

    # print(getAllItems(items, categories))
    # print(getCatagoryItems("Basketball"))
    # print(getItemDescription("Basketball", "Player"))
