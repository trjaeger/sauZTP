import napalm_star_wars
sw = napalm_star_wars.napalm_star_wars()

obi = sw.universe.individual.add("Obi-Wan Kenobi")
obi.affiliation = "REBEL_ALLIANCE"
obi.age = 57

luke = sw.universe.individual.add("Luke Skywalker")
luke.affiliation = "REBEL_ALLIANCE"
luke.age = 19

darth = sw.universe.individual.add("Darth Vader")
darth.affiliation = "EMPIRE"
darth.age = 42

yoda = sw.universe.individual.add("Yoda")
yoda.affiliation = "REBEL_ALLIANCE"
yoda.age = 896

import json
print(json.dumps(sw.get(), indent=4))
