from typing import Protocol

class FixLoop(Protocol):
    def remediate_and_retest(self, scan_id: str, agent_id: str) -> bool:
        ...
        
class MockFixLoop:
    def remediate_and_retest(self, scan_id: str, agent_id: str) -> bool:
        # Do not claim a fix is verified unless replay tests have actually executed.
        # This is just a stub interface.
        return False
