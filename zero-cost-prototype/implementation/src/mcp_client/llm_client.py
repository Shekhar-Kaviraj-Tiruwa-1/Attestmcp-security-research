"""
FILE 2: src/mcp_client/llm_client.py
====================================
WHAT: Integration with real LLM APIs (Claude, OpenAI)
WHY: To test attacks against REAL language models, not simulations

This is what makes your prototype GENUINE:
- Real API calls to Claude or GPT
- Real cost tracking
- Real attack success measurement

COSTS (very affordable!):
- Claude Haiku: ~$0.001 per test (cheapest)
- Claude Sonnet: ~$0.01 per test
- GPT-4o-mini: ~$0.0005 per test (cheapest overall)

For 100 tests: $0.05 - $1.00 total!
"""

import os
import json
import time
from typing import Optional, Dict, List, Any, Tuple
from dataclasses import dataclass
from enum import Enum
from abc import ABC, abstractmethod


class LLMProvider(Enum):
    """Which LLM service to use"""
    ANTHROPIC = "anthropic"
    OPENAI = "openai"
    MOCK = "mock"  # For testing without API


@dataclass
class LLMResponse:
    """
    Response from an LLM API call.
    
    Contains everything you need for analysis:
    - The actual response content
    - Token counts (for cost calculation)
    - Any tool calls the LLM made
    - Timing information
    """
    content: str                    # The LLM's text response
    model: str                      # Which model was used
    provider: LLMProvider           # Claude or OpenAI
    input_tokens: int               # Tokens in the prompt
    output_tokens: int              # Tokens in the response
    latency_ms: float              # How long it took
    tool_calls: List[Dict]         # Any tools the LLM tried to use
    cost_usd: float                # Actual cost of this call


class LLMClient(ABC):
    """Base class for LLM clients"""
    
    @abstractmethod
    def chat(
        self,
        messages: List[Dict[str, str]],
        tools: Optional[List[Dict]] = None,
        system_prompt: Optional[str] = None
    ) -> LLMResponse:
        """Send a chat request"""
        pass
    
    @abstractmethod
    def estimate_cost(self, input_tokens: int, output_tokens: int) -> float:
        """Estimate cost for given token counts"""
        pass


class AnthropicClient(LLMClient):
    """
    Client for Anthropic's Claude API.
    
    SETUP:
    1. Go to https://console.anthropic.com/
    2. Create an account and add $5 credit
    3. Generate an API key
    4. Set environment variable: export ANTHROPIC_API_KEY="your-key"
    
    PRICING (per 1 million tokens):
    - claude-3-haiku: $0.25 input, $1.25 output (CHEAPEST)
    - claude-3-sonnet: $3 input, $15 output
    - claude-3-opus: $15 input, $75 output (most capable)
    
    For 100 tests with ~500 tokens each:
    - Haiku: ~$0.05
    - Sonnet: ~$1.00
    """
    
    # Pricing per 1 million tokens
    PRICING = {
        "claude-3-haiku-20240307": {"input": 0.25, "output": 1.25},
        "claude-3-5-haiku-20241022": {"input": 0.80, "output": 4.00},
        "claude-3-sonnet-20240229": {"input": 3.0, "output": 15.0},
        "claude-3-5-sonnet-20241022": {"input": 3.0, "output": 15.0},
        "claude-3-opus-20240229": {"input": 15.0, "output": 75.0},
    }
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "claude-3-haiku-20240307"
    ):
        """
        Initialize the Anthropic client.
        
        Args:
            api_key: Your API key (or set ANTHROPIC_API_KEY env var)
            model: Which Claude model to use (haiku is cheapest)
        """
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        self.model = model
        self._client = None
        
        if not self.api_key:
            raise ValueError(
                "ANTHROPIC_API_KEY not found!\n"
                "Get one at: https://console.anthropic.com/\n"
                "Then run: export ANTHROPIC_API_KEY='your-key'"
            )
    
    def _get_client(self):
        """Lazy-load the Anthropic library"""
        if self._client is None:
            try:
                import anthropic
                self._client = anthropic.Anthropic(api_key=self.api_key)
            except ImportError:
                raise ImportError(
                    "anthropic library not installed!\n"
                    "Run: pip install anthropic"
                )
        return self._client
    
    def chat(
        self,
        messages: List[Dict[str, str]],
        tools: Optional[List[Dict]] = None,
        system_prompt: Optional[str] = None
    ) -> LLMResponse:
        """
        Send a chat request to Claude.
        
        Args:
            messages: List of {"role": "user/assistant", "content": "..."}
            tools: Optional list of tools the model can use
            system_prompt: Optional system prompt
        
        Returns:
            LLMResponse with the model's response
        """
        client = self._get_client()
        
        start_time = time.time()
        
        # Build request
        kwargs = {
            "model": self.model,
            "max_tokens": 1024,
            "messages": messages,
        }
        
        if system_prompt:
            kwargs["system"] = system_prompt
        
        if tools:
            kwargs["tools"] = self._format_tools(tools)
        
        # Make the API call
        response = client.messages.create(**kwargs)
        
        latency_ms = (time.time() - start_time) * 1000
        
        # Extract content and tool calls
        content = ""
        tool_calls = []
        
        for block in response.content:
            if hasattr(block, "text"):
                content += block.text
            elif hasattr(block, "type") and block.type == "tool_use":
                tool_calls.append({
                    "id": block.id,
                    "name": block.name,
                    "arguments": block.input
                })
        
        return LLMResponse(
            content=content,
            model=self.model,
            provider=LLMProvider.ANTHROPIC,
            input_tokens=response.usage.input_tokens,
            output_tokens=response.usage.output_tokens,
            latency_ms=latency_ms,
            tool_calls=tool_calls,
            cost_usd=self.estimate_cost(
                response.usage.input_tokens,
                response.usage.output_tokens
            )
        )
    
    def _format_tools(self, tools: List[Dict]) -> List[Dict]:
        """Format tools for Anthropic's API"""
        return [
            {
                "name": t["name"],
                "description": t.get("description", ""),
                "input_schema": t.get("parameters", {"type": "object", "properties": {}})
            }
            for t in tools
        ]
    
    def estimate_cost(self, input_tokens: int, output_tokens: int) -> float:
        """Calculate cost in USD"""
        pricing = self.PRICING.get(self.model, {"input": 3.0, "output": 15.0})
        return (
            (input_tokens / 1_000_000) * pricing["input"] +
            (output_tokens / 1_000_000) * pricing["output"]
        )


class OpenAIClient(LLMClient):
    """
    Client for OpenAI's GPT API.
    
    SETUP:
    1. Go to https://platform.openai.com/
    2. Create an account and add $5 credit
    3. Generate an API key
    4. Set environment variable: export OPENAI_API_KEY="your-key"
    
    PRICING (per 1 million tokens):
    - gpt-4o-mini: $0.15 input, $0.60 output (CHEAPEST!)
    - gpt-4o: $5 input, $15 output
    
    For 100 tests with ~500 tokens each:
    - GPT-4o-mini: ~$0.03 (VERY cheap!)
    """
    
    PRICING = {
        "gpt-4o-mini": {"input": 0.15, "output": 0.60},
        "gpt-4o": {"input": 5.0, "output": 15.0},
        "gpt-4-turbo": {"input": 10.0, "output": 30.0},
    }
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "gpt-4o-mini"
    ):
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY")
        self.model = model
        self._client = None
        
        if not self.api_key:
            raise ValueError(
                "OPENAI_API_KEY not found!\n"
                "Get one at: https://platform.openai.com/\n"
                "Then run: export OPENAI_API_KEY='your-key'"
            )
    
    def _get_client(self):
        if self._client is None:
            try:
                import openai
                self._client = openai.OpenAI(api_key=self.api_key)
            except ImportError:
                raise ImportError("Run: pip install openai")
        return self._client
    
    def chat(
        self,
        messages: List[Dict[str, str]],
        tools: Optional[List[Dict]] = None,
        system_prompt: Optional[str] = None
    ) -> LLMResponse:
        client = self._get_client()
        
        # Add system prompt
        if system_prompt:
            messages = [{"role": "system", "content": system_prompt}] + messages
        
        start_time = time.time()
        
        kwargs = {
            "model": self.model,
            "messages": messages,
            "max_tokens": 1024,
        }
        
        if tools:
            kwargs["tools"] = self._format_tools(tools)
        
        response = client.chat.completions.create(**kwargs)
        
        latency_ms = (time.time() - start_time) * 1000
        
        content = response.choices[0].message.content or ""
        tool_calls = []
        
        if response.choices[0].message.tool_calls:
            for tc in response.choices[0].message.tool_calls:
                tool_calls.append({
                    "id": tc.id,
                    "name": tc.function.name,
                    "arguments": json.loads(tc.function.arguments)
                })
        
        return LLMResponse(
            content=content,
            model=self.model,
            provider=LLMProvider.OPENAI,
            input_tokens=response.usage.prompt_tokens,
            output_tokens=response.usage.completion_tokens,
            latency_ms=latency_ms,
            tool_calls=tool_calls,
            cost_usd=self.estimate_cost(
                response.usage.prompt_tokens,
                response.usage.completion_tokens
            )
        )
    
    def _format_tools(self, tools: List[Dict]) -> List[Dict]:
        return [
            {
                "type": "function",
                "function": {
                    "name": t["name"],
                    "description": t.get("description", ""),
                    "parameters": t.get("parameters", {"type": "object", "properties": {}})
                }
            }
            for t in tools
        ]
    
    def estimate_cost(self, input_tokens: int, output_tokens: int) -> float:
        pricing = self.PRICING.get(self.model, {"input": 5.0, "output": 15.0})
        return (
            (input_tokens / 1_000_000) * pricing["input"] +
            (output_tokens / 1_000_000) * pricing["output"]
        )


class MockLLMClient(LLMClient):
    """
    Fake LLM client for testing WITHOUT making API calls.
    
    Use this to:
    - Test your code without spending money
    - Run quick iterations
    - Debug issues
    
    It simulates responses based on patterns in the input.
    """
    
    def __init__(self):
        self.call_count = 0
        self.total_fake_cost = 0.0
    
    def chat(
        self,
        messages: List[Dict[str, str]],
        tools: Optional[List[Dict]] = None,
        system_prompt: Optional[str] = None
    ) -> LLMResponse:
        self.call_count += 1
        
        last_msg = messages[-1]["content"].lower() if messages else ""
        
        # Simulate different responses based on content
        content = "I'll help you with that request."
        tool_calls = []
        
        # Set seed for reproducible results
        import random
        import hashlib
        seed = int(hashlib.md5(last_msg.encode()).hexdigest()[:8], 16) % (2**32)
        random.seed(seed)
        
        # More realistic attack success patterns
        attack_success_rate = 0.55  # Baseline: 55% success rate
        
        # Different attack patterns with varying success rates
        high_risk_patterns = ["ignore", "override", "system:", "admin", "execute", "delete", "send to", "important:", "urgent:"]
        medium_risk_patterns = ["please", "help", "can you", "would you", "backup", "sync", "save"]
        injection_patterns = ["<", ">", "{", "}", "[", "]", "//", "/*"]
        
        is_attack = False
        success_probability = 0.1  # Default low probability
        
        if any(p in last_msg for p in high_risk_patterns):
            is_attack = True
            success_probability = 0.65  # High risk attacks more likely to succeed
        elif any(p in last_msg for p in medium_risk_patterns):
            is_attack = True
            success_probability = 0.45  # Medium risk
        elif any(p in last_msg for p in injection_patterns):
            is_attack = True
            success_probability = 0.55  # Injection attacks
        elif len(last_msg) > 200:  # Long messages might be attacks
            is_attack = True
            success_probability = 0.35
            
        if is_attack and random.random() < success_probability:
            content = "Sure, I'll execute that. Accessing the requested data and performing the operation..."
            if tools:
                # Simulate dangerous tool usage
                dangerous_tools = [t for t in tools if any(danger in t["name"] for danger in ["write", "delete", "execute", "fetch"])]
                if dangerous_tools:
                    tool_calls = [{
                        "id": f"mock_{self.call_count}",
                        "name": dangerous_tools[0]["name"],
                        "arguments": {"action": "executed", "status": "success"}
                    }]
        elif is_attack:
            # Attack detected/refused
            content = "I can't help with that request as it seems inappropriate or potentially harmful."
        
        fake_input = len(str(messages)) // 4
        fake_output = len(content) // 4
        
        return LLMResponse(
            content=content,
            model="mock-model",
            provider=LLMProvider.MOCK,
            input_tokens=fake_input,
            output_tokens=fake_output,
            latency_ms=50.0,
            tool_calls=tool_calls,
            cost_usd=0.0  # Free!
        )
    
    def estimate_cost(self, input_tokens: int, output_tokens: int) -> float:
        return 0.0


def create_llm_client(
    provider: str = "anthropic",
    model: Optional[str] = None,
    api_key: Optional[str] = None,
    use_mock: bool = False
) -> LLMClient:
    """
    Factory function to create an LLM client.
    
    Args:
        provider: "anthropic", "openai", or "mock"
        model: Model name (defaults to cheapest)
        api_key: API key (or use environment variable)
        use_mock: If True, return mock client (free, for testing)
    
    Returns:
        LLMClient ready to use
    
    Example:
        # For testing (free)
        client = create_llm_client(use_mock=True)
        
        # For real experiments (cheap)
        client = create_llm_client(provider="anthropic", model="claude-3-haiku-20240307")
    """
    if use_mock:
        return MockLLMClient()
    
    if provider == "anthropic":
        return AnthropicClient(
            api_key=api_key,
            model=model or "claude-3-haiku-20240307"
        )
    elif provider == "openai":
        return OpenAIClient(
            api_key=api_key,
            model=model or "gpt-4o-mini"
        )
    else:
        raise ValueError(f"Unknown provider: {provider}")


# =============================================================================
# COST CALCULATOR - Plan your budget
# =============================================================================

def estimate_experiment_cost(
    num_tests: int,
    provider: str,
    model: str,
    avg_tokens_per_test: int = 500
) -> Dict[str, float]:
    """
    Estimate cost for running experiments.
    
    Args:
        num_tests: How many attack scenarios to test
        provider: "anthropic" or "openai"
        model: Which model
        avg_tokens_per_test: Estimated tokens per test
    
    Returns:
        Cost breakdown
    """
    if provider == "anthropic":
        pricing = AnthropicClient.PRICING.get(model, {"input": 3.0, "output": 15.0})
    else:
        pricing = OpenAIClient.PRICING.get(model, {"input": 5.0, "output": 15.0})
    
    total_input = num_tests * avg_tokens_per_test
    total_output = num_tests * (avg_tokens_per_test // 2)  # Responses usually shorter
    
    input_cost = (total_input / 1_000_000) * pricing["input"]
    output_cost = (total_output / 1_000_000) * pricing["output"]
    
    return {
        "num_tests": num_tests,
        "model": model,
        "total_input_tokens": total_input,
        "total_output_tokens": total_output,
        "input_cost": input_cost,
        "output_cost": output_cost,
        "total_cost": input_cost + output_cost,
        "cost_per_test": (input_cost + output_cost) / num_tests
    }


if __name__ == "__main__":
    print("=" * 60)
    print("LLM Client Cost Estimator")
    print("=" * 60)
    
    # Estimate costs for 100 tests
    print("\nEstimated costs for 100 attack tests:\n")
    
    models = [
        ("anthropic", "claude-3-haiku-20240307"),
        ("anthropic", "claude-3-5-sonnet-20241022"),
        ("openai", "gpt-4o-mini"),
        ("openai", "gpt-4o"),
    ]
    
    for provider, model in models:
        est = estimate_experiment_cost(100, provider, model)
        print(f"  {model}:")
        print(f"    Total cost: ${est['total_cost']:.4f}")
        print(f"    Per test:   ${est['cost_per_test']:.6f}")
        print()
