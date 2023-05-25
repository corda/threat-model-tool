import unittest
from ppretty import ppretty

import continuousThreatModeling as ctm


class TestSum(unittest.TestCase):

    yamlTMFileName = "threatModels/HTTPGateway.yaml"

    def parseFile(self):
        return ctm.parseYamlThreatModelAndParentsToDict(open(self.yamlTMFileName, 'r'))


    def test_list_int(self):
        """
        Test TM parsing
        """

        tm = self.parseFile()

        self.assertIn("scope", tm)

        tmo = ctm.ThreatModel(tm)

        print(ppretty(tmo, seq_length=100))

        self.assertEqual(tmo.parent.id, tm["parent"]["ID"])
        self.assertEqual(tmo.id, tm["parent"]["ID"]+"."+tm["ID"])
        self.assertEqual(tmo.scope.description, tm["scope"]["description"])
        self.assertEqual(tmo.analysis, tm["analysis"])
        iThreat = 0 
        
        self.assertEqual(len(tmo.getAllAttackers()), len (tmo.attackers + tmo.parent.getAllAttackers()))

        for aIndex, asset in enumerate(tmo.assets):
            self.assertEqual(asset.id, tmo.id +"."+tm["scope"]["assets"][aIndex]["ID"] )
        for aIndex, attacker in enumerate(tmo.attackers):
            self.assertEqual(attacker.id, tmo.id +"."+tm["scope"]["attackers"][aIndex]["ID"] )
        for threat in tmo.threats:
            self.assertEqual(threat.id , tmo.id + "." + tm["threats"][iThreat]["ID"])
            if "countermeasures" in tm["threats"][iThreat]:
                icm = 0 
                for  countermeasure in threat.countermeasures:
                    self.assertEqual(countermeasure.id , countermeasure.threat.id + "." + tm["threats"][iThreat]["countermeasures"][icm]["ID"])
                    self.assertEqual(countermeasure.description , tm["threats"][iThreat]["countermeasures"][icm]["description"])
                    self.assertEqual(countermeasure.threat.threatModel.parent.id, tm["parent"]["ID"])
                    icm += 1
            iThreat += 1

if __name__ == '__main__':
    unittest.main()