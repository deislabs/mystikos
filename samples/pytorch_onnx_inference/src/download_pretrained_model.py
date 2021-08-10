from torchvision import models
import torch

output_filename = "/app/alexnet-pretrained.pt"
alexnet = models.alexnet(pretrained=True)
torch.save(alexnet, output_filename)

# Export model to onnx
x = torch.randn(1, 3, 224, 224, requires_grad=True)
torch.onnx.export(alexnet, x, "/app/alexnet-pretrained.onnx")
