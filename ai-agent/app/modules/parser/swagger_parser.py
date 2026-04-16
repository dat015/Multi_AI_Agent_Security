from prance import ResolvingParser

class SwaggerParser:
    @staticmethod
    def parse(source: str):
        # Sử dụng ResolvingParser để tự động xử lý tất cả $ref
        parser = ResolvingParser(source)
        return parser.specification # Trả về dict đã được giải quyết hết các tham chiếu