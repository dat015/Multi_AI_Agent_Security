import os
import json
from datetime import datetime

from langchain_protocol import Union

def save_markdown_file(
    content: Union[str, dict, list],
    file_name: str,
    output_dir: str = "output",
    use_timestamp: bool = True
) -> str:
    """
    Lưu dữ liệu ra file markdown (.md).

    Args:
        content (str | dict | list):
            Nội dung markdown hoặc object.

        file_name (str):
            Tên file (không cần .md)

        output_dir (str):
            Thư mục output.

        use_timestamp (bool):
            Có thêm timestamp hay không.

    Returns:
        str:
            Đường dẫn file đã lưu.
    """

    os.makedirs(output_dir, exist_ok=True)

    if use_timestamp:
        timestamp = datetime.now().strftime(
            "%Y%m%d_%H%M%S"
        )

        full_file_name = (
            f"{file_name}_{timestamp}.md"
        )
    else:
        full_file_name = (
            f"{file_name}.md"
        )

    file_path = os.path.join(
        output_dir,
        full_file_name
    )

    markdown_content = ""

    # Nếu là dict/list → pretty JSON
    if isinstance(content, (dict, list)):
        markdown_content = (
            "```json\n"
            + json.dumps(
                content,
                ensure_ascii=False,
                indent=2
            )
            + "\n```"
        )

    else:
        markdown_content = str(content)

    with open(
        file_path,
        "w",
        encoding="utf-8"
    ) as f:
        f.write(markdown_content)

    print(
        f"[✓] Saved markdown file: {file_path}"
    )

    return file_path
def save_json_file(
    data: dict,
    file_name: str,
    output_dir: str = "output",
    use_timestamp: bool = True
) -> str:
    """
    Lưu dữ liệu JSON ra file.

    Args:
        data (dict):
            Dữ liệu cần lưu.

        file_name (str):
            Tên file (không cần .json)

        output_dir (str):
            Thư mục output.

        use_timestamp (bool):
            Có thêm timestamp hay không.

    Returns:
        str:
            Đường dẫn file đã lưu.
    """

    os.makedirs(output_dir, exist_ok=True)

    if use_timestamp:
        timestamp = datetime.now().strftime(
            "%Y%m%d_%H%M%S"
        )

        full_file_name = (
            f"{file_name}_{timestamp}.json"
        )
    else:
        full_file_name = (
            f"{file_name}.json"
        )

    file_path = os.path.join(
        output_dir,
        full_file_name
    )

    with open(
        file_path,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            data,
            f,
            ensure_ascii=False,
            indent=2
        )

    print(
        f"[✓] Saved file: {file_path}"
    )

    return file_path