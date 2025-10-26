from datetime import datetime, timezone
from uuid import uuid4
from typing import Any, Dict
import json
import os
from dotenv import load_dotenv
from uagents import Context, Model, Protocol, Agent
from hyperon import MeTTa

from uagents_core.contrib.protocols.chat import (
    ChatAcknowledgement,
    ChatMessage,
    EndSessionContent,
    StartSessionContent,
    TextContent,
    chat_protocol_spec,
)

from metta.incidentrag import IncidentRAG
from metta.knowledge import initialize_knowledge_graph
from metta.utils import LLM, process_query


load_dotenv()


agent = Agent(
    name="Incident Response MeTTa Agent",
    seed=os.getenv("AGENT_SEED", "incident_metta_2025"),
    port=8003,
    mailbox=True,
    publish_agent_details=True,
)


def create_text_chat(text: str, end_session: bool = False) -> ChatMessage:
    """Create a formatted chat message for the response."""
    content = [TextContent(type="text", text=text)]
    if end_session:
        content.append(EndSessionContent(type="end-session"))
    return ChatMessage(
        timestamp=datetime.now(timezone.utc),
        msg_id=uuid4(),
        content=content,
    )


metta = MeTTa()
initialize_knowledge_graph(metta)
rag = IncidentRAG(metta)
llm = LLM(api_key=os.getenv("ASI_ONE_API_KEY"))


chat_proto = Protocol(spec=chat_protocol_spec)

@chat_proto.on_message(ChatMessage)
async def handle_message(ctx: Context, sender: str, msg: ChatMessage):
    """Handle incoming chat messages and process incident queries."""
    ctx.storage.set(str(ctx.session), sender)

    # Acknowledge receipt
    await ctx.send(
        sender,
        ChatAcknowledgement(
            timestamp=datetime.now(timezone.utc),
            acknowledged_msg_id=msg.msg_id,
        ),
    )

    for item in msg.content:
        if isinstance(item, StartSessionContent):
            ctx.logger.info(f"🟢 Start session message from {sender}")
            continue

        elif isinstance(item, TextContent):
            user_query = item.text.strip()
            ctx.logger.info(f"🔍 Received cybersecurity query from {sender}: {user_query}")

            try:
                # Process query with MeTTa RAG and ASI LLM
                response = process_query(user_query, rag, llm)

                if isinstance(response, dict):
                    answer_text = (
                        f"**{response.get('selected_question', user_query)}**\n\n"
                        f"{response.get('humanized_answer', 'I could not process your query.')}"
                    )
                else:
                    answer_text = str(response)

                await ctx.send(sender, create_text_chat(answer_text))

            except Exception as e:
                ctx.logger.error(f"❌ Error processing incident query: {e}")
                await ctx.send(
                    sender,
                    create_text_chat(
                        "⚠️ I encountered an error analyzing this incident. Please try again."
                    ),
                )
        else:
            ctx.logger.info(f"📨 Received unexpected content type from {sender}")

@chat_proto.on_message(ChatAcknowledgement)
async def handle_ack(ctx: Context, sender: str, msg: ChatAcknowledgement):
    """Handle chat acknowledgements."""
    ctx.logger.info(f"✅ Acknowledged message from {sender} for {msg.acknowledged_msg_id}")


@agent.on_event("startup")
async def startup(ctx: Context):
    """Agent startup banner and details."""
    ctx.logger.info("=" * 60)
    ctx.logger.info("🛡️  CYBERSECURITY INCIDENT RESPONSE METTA AGENT")
    ctx.logger.info("🤖  Powered by ASI:One + MeTTa Reasoning Framework")
    ctx.logger.info("=" * 60)
    ctx.logger.info(f"📬 Agent Address: {agent.address}")
    ctx.logger.info(f"🌐 Mailbox: ENABLED")
    ctx.logger.info("")
    ctx.logger.info("Ready to analyze and respond to cybersecurity incidents!")
    ctx.logger.info("=" * 60)

@agent.on_event("shutdown")
async def shutdown(ctx: Context):
    """Agent shutdown handler."""
    ctx.logger.info("🛡️ Shutting down Cybersecurity MeTTa Agent...")


agent.include(chat_proto, publish_manifest=True)

if __name__ == "__main__":
    print("\n" + "="*60)
    print("🛡️  CYBERSECURITY INCIDENT RESPONSE METTA AGENT")
    print("    Matching Medical Agent Structure + Chat Protocol")
    print("="*60)
    print(f"\n📬 Agent Address: {agent.address}")
    print(f"🌐 Mailbox: ENABLED")
    print(f"💬 Protocol: chat_protocol_spec (uAgents Chat)")
    print(f"\n🔥 Flow:")
    print("  User Query → MeTTa RAG → ASI LLM → Structured Response")
    print(f"\n🚀 Features:")
    print("  • MITRE ATT&CK Knowledge Graph")
    print("  • Dynamic MeTTa reasoning")
    print("  • ASI:One LLM integration")
    print("  • Real-time Chat Protocol for Human-Agent Interaction")
    print("="*60 + "\n")

    agent.run()