import importlib.util, tempfile, unittest
from pathlib import Path
import yaml
SCRIPT=Path(__file__).resolve().parents[1]/'.cursor/skills/code-quality-auditor/scripts/auditor.py'
spec=importlib.util.spec_from_file_location('auditor',SCRIPT);a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)
class AuditorTests(unittest.TestCase):
 def setUp(self):
  self.reg=a.load(a.HERE/'config/checks.yaml')['checks']
  self.conf=a.load(a.HERE/'quality-auditor.yaml')
 def test_catalog(self):
  self.assertFalse(a.catalog_validation(a.load(a.HERE/'config/metrics.yaml')['metrics'],self.reg))
 def test_all_enabled(self):
  selected,_=a.resolve_profile('full',self.conf,self.reg)
  self.assertEqual(set(self.reg),selected)
 def test_fast_excludes_mutation(self):
  selected,_=a.resolve_profile('fast',self.conf,self.reg)
  self.assertNotIn('mutation_testing',selected)
 def test_include_only(self):
  c={**self.conf,'profiles':{'focused':{'include':['dead_code','duplication']}}}
  selected,_=a.resolve_profile('focused',c,self.reg)
  self.assertEqual(selected,{'dead_code','duplication'})
 def test_reinclude_parent_exclusion(self):
  c={**self.conf,'profiles':{'child':{'extends':'fast','include':['mutation_testing']}}}
  selected,_=a.resolve_profile('child',c,self.reg)
  self.assertIn('mutation_testing',selected)
 def test_exclusion_wins(self):
  c={**self.conf,'profiles':{'focused':{'include':['dead_code'],'exclude':['dead_code']}}}
  self.assertFalse(a.resolve_profile('focused',c,self.reg)[0])
 def test_unknown_check_fails(self):
  with self.assertRaises(ValueError):a.resolve_profile('x',{'profiles':{'x':{'include':['invalid']}}},self.reg)
 def test_dag(self):
  d=a.dag({'dead_code','mutation_testing'},self.reg)
  self.assertIn('symbol_index',d);self.assertIn('testing',d)
 def test_static_syntax(self):
  with tempfile.TemporaryDirectory() as t:
   p=Path(t);(p/'bad.py').write_text('def broken(\n')
   files,langs=a.discover(p);findings,_=a.source_static(p,files)
   self.assertEqual(langs['python'],1)
   self.assertTrue(any(f['confidence']=='confirmed' for f in findings))
 def test_no_autoinstall(self):
  code=SCRIPT.read_text()
  self.assertNotIn('pip install',code)
if __name__=='__main__':unittest.main()
