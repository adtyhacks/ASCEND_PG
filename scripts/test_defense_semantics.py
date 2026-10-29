def result(command_ok, query=None, expected="DOWN"):
    return {"defense_command_succeeded":command_ok,"defense_effect_verified":bool(command_ok and query and query.get("state")==expected)}
def main():
    assert result(True,{"state":"DOWN"})["defense_effect_verified"]
    assert not result(True,None)["defense_effect_verified"]
    assert not result(True,{"state":"UP"})["defense_effect_verified"]
    print("defense semantics: PASS")
if __name__=='__main__': main()
