import json
import os
os.chdir('..')
with open(os.path.abspath(os.curdir) + '/static/publicSeed.json') as df:
    data = json.load(df)
    Categories = map(lambda x: x["Name"], data["Category"])

    Items = map(lambda x: x["Item"], data["Category"])

    def a(arrs, cas):
        Ites = []
        arrsLength = len(arrs)
        casLength = len(cas)
        for x in xrange(arrsLength):
            s = cas[x]
            for y in xrange(len(arrs[x])):
                Ites.append(arrs[x][y]["Title"] + "(" + s + ")")
        return Ites

    Items = a(Items, Categories)
    print(Items)
