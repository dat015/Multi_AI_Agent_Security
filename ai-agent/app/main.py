from app.modules.parser.swagger_parser import SwaggerParser
from app.modules.agent.agent import AIAgent
from app.core.constants import SWAGGER_DEFAULT_PATH


def main():
    # Parse swagger
    spec = SwaggerParser.parse(SWAGGER_DEFAULT_PATH)

    agent = AIAgent()

    prompt = f"""
    Here is swagger spec:
    {spec}

    Summarize all endpoints.
    """

    result = agent.ask(prompt)

    print(result)


if __name__ == "__main__":
    main()