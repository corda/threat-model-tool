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
    # CM_PREPARED_STATEMENTS is NOT operational in the enhanced model
    assert cm.operational is False
    assert cm.tested is True
    assert cm.testRef == "test-001"
    assert cm.ticketLink == "https://jira.example.com/browse/DEV-456"

def test_operational_countermeasures(full_tm):
    """Test operational countermeasures with different operators."""
    threat = next(t for t in full_tm.threats if t._id == "THREAT_KEY_COMPROMISE")
    cm_rotation = next(c for c in threat.countermeasures if c._id == "CM_KEY_ROTATION")
    cm_vault = next(c for c in threat.countermeasures if c._id == "CM_KEY_VAULT")
    
    assert cm_rotation.operational is True
    assert cm_rotation.operator == "Security Operations Team"
    assert cm_vault.operational is True
    assert cm_vault.operator == "Platform Team"

def test_child_model_loading(full_tm):
    """Test that children are correctly loaded and linked."""
    # The child TM ID is usually Parent.Child
    child = next((c for c in full_tm.children if c.id == "FullFeature.SubComponent"), None)
    assert child is not None
    assert child.parent == full_tm
    
    # Check threat in child model (updated to SUB_THREAT_DOS)
    sub_threat = next((t for t in child.threats if t._id == "SUB_THREAT_DOS"), None)
    assert sub_threat is not None
    # SUB_THREAT_DOS impacts OBJ_AVAILABILITY
    assert sub_threat.impactedSecObjs[0]._id == "OBJ_AVAILABILITY"

def test_second_child_model(full_tm):
    """Test the second child threat model (ApiGateway)."""
    api_gateway = next((c for c in full_tm.children if c.id == "FullFeature.ApiGateway"), None)
    assert api_gateway is not None
    
    # Check ApiGateway has correct threats
    jwt_threat = next((t for t in api_gateway.threats if t._id == "GW_JWT_FORGERY"), None)
    assert jwt_threat is not None
    assert jwt_threat.CVSS["base"] == 9.1

def test_dataflow_inscope(full_tm):
    """Test dataflow assets with inScope: false."""
    # DATAFLOW_EXTERNAL_API should have inScope: false
    dataflow = next((a for a in full_tm.assets if a._id == "DATAFLOW_EXTERNAL_API"), None)
    assert dataflow is not None
    assert dataflow._inScope is False
    assert dataflow.type == "dataflow"

def test_key_assets(full_tm):
    """Test key/credential assets for Keys Summary."""
    api_key = next((a for a in full_tm.assets if a._id == "API_KEY"), None)
    assert api_key is not None
    assert api_key.type == "key"
    assert api_key.properties["type"] == "Ed25519"
    
    db_cred = next((a for a in full_tm.assets if a._id == "DB_CREDENTIAL"), None)
    assert db_cred is not None
    assert db_cred.type == "credential"

def test_refid_countermeasure(full_tm):
    """Test REFID countermeasures within same threat model."""
    child = next((c for c in full_tm.children if c.id == "FullFeature.SubComponent"), None)
    key_threat = next((t for t in child.threats if t._id == "SUB_THREAT_KEY_LEAK"), None)
    
    # Should have resolved REFID countermeasure
    assert len(key_threat.countermeasures) >= 2
    # One is a REFID to SUB_CM_RATE_LIMIT
    refid_cm = next((c for c in key_threat.countermeasures if c._id == "SUB_CM_RATE_LIMIT"), None)
    assert refid_cm is not None
