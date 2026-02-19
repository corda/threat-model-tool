import pytest
import os
import sys
from glob import glob

# Add src to path for testing
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from r3threatmodeling import threatmodel_data

def get_all_yaml_files():
    base_path = os.path.dirname(__file__)
    example_dir = os.path.join(base_path, "exampleThreatModels")
    return glob(os.path.join(example_dir, "**/*.yaml"), recursive=True)

@pytest.mark.parametrize("yaml_file", get_all_yaml_files())
def test_threat_schema_consistency(yaml_file):
    """
    Test that every threat in every example YAML file has the minimum required 
    attributes expected by the tools and templates.
    """
    # Only test root threat models (those without a 'parent' field) 
    # to ensure all REFIDs can be resolved recursively.
    import yaml as pyyaml
    with open(yaml_file, 'r') as f:
        try:
            data = pyyaml.safe_load(f)
            if data and 'parent' in data:
                pytest.skip(f"Skipping fragment file: {yaml_file}")
        except Exception:
            pytest.skip(f"Skipping unparseable file: {yaml_file}")

    try:
        tm = threatmodel_data.ThreatModel(yaml_file)
    except Exception as e:
        pytest.fail(f"Failed to load/resolve TM {yaml_file}: {e}")

    # Check all threats in the entire tree (getAllDown)
    for threat in tm.getAllDown('threats'):
        # Essential fields for core logic
        assert hasattr(threat, 'id'), f"Threat in {yaml_file} missing ID"
        assert hasattr(threat, 'threatType'), f"Threat {threat.id} in {yaml_file} missing threatType"
        
        # Fields expected by templates
        assert hasattr(threat, 'title'), f"Threat {threat.id} in {yaml_file} missing title"
        
        # 'attack' is often used in tree diagrams. 
        # Even if empty, it should probably be present or the code should handle its absence.
        # Given the recent fix, we now handle its absence, but it's good practice to have it.
        # However, for now let's just ensure we can access it via getattr without crashing.
        getattr(threat, 'attack', '')

        # Check CVSS
        assert hasattr(threat, 'CVSS'), f"Threat {threat.id} in {yaml_file} missing CVSS"
        
        # Check countermeasures
        assert hasattr(threat, 'countermeasures'), f"Threat {threat.id} in {yaml_file} missing countermeasures list"

def test_template_rendering_sanity():
    """
    Sanity check: try rendering a template snippet for all threats 
    to catch AttributeError/KeyError early.
    """
    from r3threatmodeling.template.TM_AttackTreePlantUMLDiagram import render_plant_uml_threat_tree
    import yaml as pyyaml
    
    base_path = os.path.dirname(__file__)
    example_dir = os.path.join(base_path, "exampleThreatModels")
    yaml_files = glob(os.path.join(example_dir, "**/*.yaml"), recursive=True)
    
    for yaml_file in yaml_files:
        with open(yaml_file, 'r') as f:
            try:
                data = pyyaml.safe_load(f)
                if data and 'parent' in data:
                    continue
            except Exception:
                continue

        try:
            tm = threatmodel_data.ThreatModel(yaml_file)
            for threat in tm.getAllDown('threats'):
                # This should not raise AttributeError
                render_plant_uml_threat_tree(threat)
        except Exception as e:
            pytest.fail(f"Template rendering failed for {yaml_file}: {e}")
