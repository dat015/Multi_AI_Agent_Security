from prance import ResolvingParser
import requests
import tempfile
import os


class SwaggerParser:

    @staticmethod
    def parse(source: str):
        """
        source: URL hoặc file path
        """

        # Nếu là URL
        if source.startswith("http"):
            response = requests.get(source)
            response.raise_for_status()

            with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp:
                tmp.write(response.content)
                tmp_path = tmp.name

            parser = ResolvingParser(tmp_path)
            os.unlink(tmp_path)

        else:
            parser = ResolvingParser(source)

        return parser.specification