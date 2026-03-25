from datasets import load_dataset
from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification,
    TrainingArguments,
    Trainer
)
import numpy as np
import evaluate

# 1. Load dataset (example)
dataset = load_dataset("imdb")  # replace with your phishing dataset

# 2. Load tokenizer
tokenizer = AutoTokenizer.from_pretrained("distilbert-base-uncased")

# 3. Tokenization
def preprocess(example):
    return tokenizer(example["text"], truncation=True, padding="max_length")

dataset = dataset.map(preprocess, batched=True)

# 4. Load model
model = AutoModelForSequenceClassification.from_pretrained(
    "distilbert-base-uncased",
    num_labels=2
)

# 5. Metrics
accuracy = evaluate.load("accuracy")

def compute_metrics(eval_pred):
    logits, labels = eval_pred
    preds = np.argmax(logits, axis=1)
    return accuracy.compute(predictions=preds, references=labels)

# 6. Training config (IMPORTANT)
training_args = TrainingArguments(
    output_dir="./trained_model",

    per_device_train_batch_size=8,
    per_device_eval_batch_size=8,
    num_train_epochs=2,

    evaluation_strategy="epoch",

    # 🔥 THIS CONNECTS TO HUGGING FACE
    push_to_hub=True,
    hub_model_id="your-username/your-repo-name"
)

# 7. Trainer
trainer = Trainer(
    model=model,
    args=training_args,
    train_dataset=dataset["train"],
    eval_dataset=dataset["test"],
    tokenizer=tokenizer,
    compute_metrics=compute_metrics
)

# 8. Train
trainer.train()

# 9. Save locally (used by your FastAPI)
trainer.save_model("./trained_model")
tokenizer.save_pretrained("./trained_model")

# 10. Push to Hugging Face
trainer.push_to_hub()
