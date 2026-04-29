import json
import yaml
import os
from prance import ResolvingParser

class SwaggerParser:
    @staticmethod
    def _fix_missing_responses(spec_dict):
        """
        Duyệt qua toàn bộ file Spec và tự động thêm trường 'responses' 
        vào các endpoint bị thiếu để tránh lỗi Validation.
        """
        if 'paths' not in spec_dict:
            return spec_dict

        for path, methods in spec_dict['paths'].items():
            # Một path có thể chứa nhiều method (get, post, put...)
            for method, details in methods.items():
                # Chỉ xử lý các HTTP Method hợp lệ
                if method.lower() in ['get', 'post', 'put', 'delete', 'patch', 'options', 'head']:
                    # QUAN TRỌNG: Nếu thiếu 'responses', tự động bổ sung
                    if 'responses' not in details:
                        details['responses'] = {
                            "200": {
                                "description": "Auto-generated response for validation bypass"
                            }
                        }
        return spec_dict

    @staticmethod
    def parse(spec_content: str, fmt: str):
        # 1. Parse từ string (KHÔNG dùng open)
        if fmt == "json":
            raw_spec = json.loads(spec_content)
        else:
            raw_spec = yaml.safe_load(spec_content)

        # 2. Fix cấu trúc
        fixed_spec = SwaggerParser._fix_missing_responses(raw_spec)

        # 3. Resolve $ref
        parser = ResolvingParser(spec_string=json.dumps(fixed_spec))
        
        return parser.specification