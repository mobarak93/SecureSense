import asyncio
import os

# Set integration test to True so that our fallback mocks are active for testing
os.environ["INTEGRATION_TEST"] = "TRUE"

from google.adk.agents.run_config import RunConfig, StreamingMode
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types

from app.agent import root_agent

async def run_query(query: str):
    session_service = InMemorySessionService()
    session = session_service.create_session_sync(user_id="test_user", app_name="securesense")
    runner = Runner(agent=root_agent, session_service=session_service, app_name="securesense")

    message = types.Content(
        role="user", parts=[types.Part.from_text(text=query)]
    )

    print(f"\nUser Query: {query}")
    print("-" * 60)

    events = runner.run(
        new_message=message,
        user_id="test_user",
        session_id=session.id,
        run_config=RunConfig(streaming_mode=StreamingMode.SSE),
    )

    for event in events:
        if event.content and event.content.parts:
            for part in event.content.parts:
                if part.text:
                    print(part.text, end="")
                elif part.function_call:
                    print(f"\n[Agent Handoff / Tool Call: {part.function_call.name} (args: {part.function_call.args})]")
    print("\n" + "=" * 60)

async def main():
    queries = [
        "How is the sky today?",  # General query (Root Orchestrator text response)
        "Analyze this network traffic log for malicious DoS patterns.",  # IDS Agent
        "Audit this configuration for compliance under NIS2 Art 21.",  # Compliance Agent
        "Compile an incident report and forensics timeline for the recent gateway breach.",  # Forensics Agent
        "Compute the system security risk score for the current posture.",  # Risk Scoring Agent
        "Check if IP 45.227.254.10 is a threat",
        "What is the criticality of a PACEMAKER_CONTROLLER?",
        "What does NIS2 require for encryption?",
    ]
    for query in queries:
        await run_query(query)

if __name__ == "__main__":
    asyncio.run(main())
