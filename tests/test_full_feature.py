import pytest
import os
import sys

# Add src to path for testing
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from r3threatmodeling import threatmodel_data

def get_test_model_path():
    base_path = os.path.dirname(__file__)
    return os.path.join(base_path, "exampleThreatModels/FullFeature/FullFeature.yaml")

@pytest.fixture
def full_tm():
    """Fixture to load the FullFeature threat model."""
    tm_path = get_test_model_path()
    return threatmodel_data.ThreatModel(tm_path)

def test_tm_metadata(full_tm):
    """Test top-level metadata parsing."""
    assert full_tm.id == "FullFeature"
    assert full_tm.title == "Comprehensive Reference Threat Model"
    assert full_tm.version == "1.0"
    assert full_tm.appliesToVersions == ">=5.1"
    assert "Jane Doe" in full_tm.authors
    assert "Initial version" in full_tm.history

def test_security_objectives(full_tm):
    """Test security objectives parsing and contributors."""
    obj_conf = next(o for o in full_tm.securityObjectives if o._id == "OBJ_CONFIDENTIALITY")
    assert obj_conf.title == "Data Confidentiality"
    assert obj_conf.inScope is True
    
    obj_int = next(o for o in full_tm.securityObjectives if o._id == "OBJ_INTEGRITY")
    # After resolution, contributesTo should contain the actual SecurityObjective objects
    contributor = obj_int.contributesTo[0]
    assert isinstance(contributor, threatmodel_data.SecurityObjective)
    assert contributor._id == "OBJ_CONFIDENTIALITY"

def test_assets_and_properties(full_tm):
    """Test assets and their nested properties."""
    asset = next(a for a in full_tm.assets if a._id == "ASSET_USER_DATA")
    assert asset.type == "data"
    assert asset._inScope is True
    assert asset.properties["TLS"] == "1.3"
    assert asset.properties["storage"] == "Encrypted DB"

def test_threat_parsing(full_tm):
    """Test detailed threat parsing including compliance and CVSS."""
    threat = next(t for t in full_tm.threats if t._id == "THREAT_SQL_INJECTION")
    assert threat.threatType == "Tampering"
    assert threat.CVSS["vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert threat.CVSS["base"] == 9.8
    assert threat.compliance["GDPR"]["ref"] == "Article 32"
    assert threat.appliesToVersions == ">=5.1"

def test_countermeasures(full_tm):
    """Test countermeasures and their operational fields."""
    threat = next(t for t in full_tm.threats if t._id == "THREAT_SQL_INJECTION")
    cm = next(c for c in threat.countermeasures if c._id == "CM_PREPARED_STATEMENTS")
    
    assert cm.title == "Use Prepared Statements"
    assert cm.inPlace is True
    assert cm.operational is True
    assert cm.tested is True
    assert cm.testRef == "test-001"
    assert cm.ticketLink == "https://jira.example.com/browse/DEV-456"

def test_child_model_loading(full_tm):
    """Test that children are correctly loaded and linked."""
    # The child TM ID is usually Parent.Child
    child = next((c for c in full_tm.children if c.id == "FullFeature.SubComponent"), None)
    assert child is not None
    assert child.parent == full_tm
    
    # Check threat in child model
    sub_threat = next((t for t in child.threats if t._id == "SUB_THREAT"), None)
    assert sub_threat is not None
    assert sub_threat.impactedSecObjs[0]._id == "OBJ_CONFIDENTIALITY"
