from torchvision import models
import torch

output_filename = "/app/alexnet-pretrained.pt"
alexnet = models.alexnet(pretrained=True)
torch.save(alexnet, output_filename)