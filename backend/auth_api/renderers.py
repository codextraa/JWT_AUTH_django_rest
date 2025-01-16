# from rest_framework.renderers import JSONRenderer


# class CustomRenderer(JSONRenderer):
#     """
#     Custom Renderer to format response data.
#     - Wraps successful JSON responses in a "data" key.
#     - Wraps error JSON responses in an "error" key.
#     - Handles binary data (e.g., images) without wrapping.
#     """

#     def render(self, data, accepted_media_type=None, renderer_context=None):
#         response = renderer_context.get("response", None)
#         request = renderer_context.get("request", None)

#         # Check for image or binary data
#         if response is not None and (
#             response.status_code >= 400 or "image" in response.get('Content-Type', '')
#         ):
#             # If it's binary data (image), skip wrapping
#             return data

#         # Handle JSON errors
#         if response is not None and response.status_code >= 400:
#             if isinstance(data, dict):
#                 data = {"error": data}
#             else:
#                 data = {"error": {"detail": data}}
            
#             data["status_code"] = response.status_code

#         # Handle JSON successful responses
#         else:
#             data = {"data": data}

#         return super().render(data, accepted_media_type, renderer_context)