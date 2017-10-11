#!/usr/bin/env python2
import json
import string
import random
import requests


def getCatagory():
    with open('./static/publicSeed.json') as data_file:
        data = json.load(data_file)
        return map(lambda x: x["Name"], data["Category"])


def getItems():
    with open('./static/publicSeed.json') as data_file:
        data = json.load(data_file)
        return map(lambda x: x["Item"], data["Category"])


def getAllItems(arrs, cas):
    items = []
    arrsLength = len(arrs)
    casLength = len(cas)
    for x in xrange(arrsLength):
        s = cas[x]
        for y in xrange(len(arrs[x])):
            items.append([arrs[x][y]["Title"], s])
    return items


def getCatagoryItems(items, categories, casName):
    items = getAllItems(items, categories)
    return filter(lambda x: x[1] == casName, items)


def getItemDescription(items, categories, casName, title):

    i = categories.index(casName)
    o = filter(lambda x: x["Title"] == title, items[i])
    return o[0]["Description"]


# print(getCatagory())
# print(getItems())
# print(getAllItems(getItems(), getCatagory()))
# print(getCatagoryItems(getItems(), getCatagory(), "Basketball"))
#print(getItemDescription(getItems(), getCatagory(), "Basketball", "Player"))


def getSeverState():
    return ''.join(
        random.choice(string.ascii_uppercase + string.digits) for x in range(32))
