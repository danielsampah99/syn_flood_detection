"""
Model Trainer for SYN Flood Detection using K-means Clustering

This script implements a Bisecting K-means clustering approach to detect unusual
patterns in network traffic time deltas, which can indicate SYN flood attacks.
It follows the approach demonstrated by the professor but with enhanced
documentation and typing.

Key features:
- Finds optimal number of clusters using silhouette scores
- Visualizes time delta patterns by cluster
- Can be used to identify attack patterns without labeled data
"""

import os
import argparse
import logging
from typing import List, Tuple, Optional, Dict, Any, Union

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.cluster import BisectingKMeans
from sklearn.metrics import silhouette_score
from sklearn.preprocessing import StandardScaler
import joblib
from pathlib import Path


# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('KMeansModelTrainer')


def find_optimal_clusters(
    X: np.ndarray,
    min_clusters: int = 2,
    max_clusters: int = 10
) -> Tuple[int, List[float]]:
    """
    Find the optimal number of clusters for K-means using silhouette score.

    The silhouette score measures how similar a point is to its own cluster
    compared to other clusters. Higher values indicate better clustering.

    Args:
        X: Feature matrix containing time delta values
        min_clusters: Minimum number of clusters to try
        max_clusters: Maximum number of clusters to try

    Returns:
        Tuple containing (optimal_clusters, silhouette_scores_list)
    """
    logger.info(f"Finding optimal number of clusters between {min_clusters} and {max_clusters}...")

    silhouette_scores: List[float] = []
    cluster_range = range(min_clusters, max_clusters + 1)

    for n_clusters in cluster_range:
        # Initialize the clustering model
        bisect_kmeans = BisectingKMeans(
            n_clusters=n_clusters,
            random_state=42,
            bisecting_strategy='largest_cluster'
        )

        # Fit and predict cluster labels
        labels = bisect_kmeans.fit_predict(X)

        # Calculate silhouette score
        # A higher score means better defined clusters
        score = silhouette_score(X, labels)
        silhouette_scores.append(score)

        logger.info(f"  Clusters: {n_clusters}, Silhouette Score: {score:.4f}")

    # Find optimal number of clusters (highest silhouette score)
    optimal_clusters = cluster_range[silhouette_scores.index(max(silhouette_scores))]
    logger.info(f"Optimal number of clusters: {optimal_clusters}")

    return optimal_clusters, silhouette_scores


def train_kmeans_model(
    feature_file: str,
    output_dir: str,
    time_col: str = 'avg_time_delta'
) -> Optional[BisectingKMeans]:
    """
    Train a Bisecting K-means clustering model on time delta features.

    This function:
    1. Loads the feature data
    2. Scales the time delta values
    3. Finds optimal number of clusters
    4. Trains the model and assigns clusters
    5. Creates visualizations similar to professor's example
    6. Saves the model for later use

    Args:
        feature_file: Path to CSV file with extracted features
        output_dir: Directory to save model and visualizations
        time_col: Column name for time delta values

    Returns:
        Trained BisectingKMeans model or None if training fails
    """
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    logger.info(f"Output directory: {output_dir}")

    # Load the features
    logger.info(f"Loading features from {feature_file}")
    try:
        df = pd.read_csv(feature_file)
        logger.info(f"Loaded {len(df)} samples with {len(df.columns)} features")
    except Exception as e:
        logger.error(f"Failed to load feature file: {e}")
        return None

    if df.empty:
        logger.error("Feature file is empty!")
        return None

    if time_col not in df.columns:
        logger.error(f"Time delta column '{time_col}' not found in features!")
        return None

    # Extract the time delta values and reshape for clustering
    X = df[[time_col]].copy()
    logger.info(f"Using '{time_col}' for clustering")

    # Scale the time delta values for better clustering
    # Clustering is sensitive to the scale of the data
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    logger.info("Scaled time delta values for optimal clustering")

    # Find optimal number of clusters
    optimal_clusters, silhouette_scores = find_optimal_clusters(
        X_scaled, min_clusters=2, max_clusters=10
    )

    # Plot silhouette scores
    plt.figure(figsize=(10, 6))
    plt.plot(range(2, len(silhouette_scores) + 2), silhouette_scores, 'o-')
    plt.axvline(x=optimal_clusters, color='r', linestyle='--')
    plt.title('Silhouette Score by Number of Clusters')
    plt.xlabel('Number of Clusters')
    plt.ylabel('Silhouette Score')
    plt.grid(True)
    plt.savefig(os.path.join(output_dir, 'silhouette_scores.png'))
    logger.info(f"Saved silhouette score plot to {output_dir}/silhouette_scores.png")

    # Train the final model with optimal number of clusters
    logger.info(f"Training final model with {optimal_clusters} clusters...")
    bisect_kmeans = BisectingKMeans(
        n_clusters=optimal_clusters,
        random_state=42,
        bisecting_strategy='largest_cluster'
    )

    # Fit model and assign cluster labels to each sample
    df['cluster'] = bisect_kmeans.fit_predict(X_scaled)

    # Save the labeled data
    output_file = os.path.join(output_dir, 'time_delta_clustered.csv')
    df.to_csv(output_file, index=False)
    logger.info(f"Saved clustered data to {output_file}")

    # VISUALIZATION 1: Scatter plot with cluster center
    plt.figure(figsize=(12, 7))
    for cluster in range(optimal_clusters):
        cluster_data = df[df['cluster'] == cluster]
        plt.scatter(
            cluster_data.index,
            cluster_data[time_col],
            label=f'Cluster {cluster}',
            alpha=0.6
        )

    # Get cluster centers and convert back to original scale
    centers = bisect_kmeans.cluster_centers_
    centers = scaler.inverse_transform(centers)

    # Add horizontal lines for cluster centers
    for idx, center in enumerate(centers):
        plt.hlines(
            center,
            xmin=0,
            xmax=len(df),
            colors='red',
            linestyles='dashed',
            alpha=0.7,
            label=f'Center {idx}: {center[0]:.6f}' if idx == 0 else f'Center {idx}: {center[0]:.6f}'
        )

    plt.title(f'Bisecting K-means Clustering (Optimal Clusters: {optimal_clusters})')
    plt.xlabel('Sample Index')
    plt.ylabel(f'Time Delta ({time_col})')
    plt.legend(loc='best')
    plt.grid(True)
    plt.savefig(os.path.join(output_dir, 'kmeans_clusters.png'))
    logger.info(f"Saved cluster visualization to {output_dir}/kmeans_clusters.png")

    # VISUALIZATION 2: Enhanced visualization with boxplot and histogram
    fig, axs = plt.subplots(1, 2, figsize=(14, 5))

    # Boxplot of time delta by cluster
    df.boxplot(column=time_col, by='cluster', grid=False, ax=axs[0])
    axs[0].set_title('Boxplot of Time Delta by Cluster')
    axs[0].set_xlabel('Cluster')
    axs[0].set_ylabel(f'Time Delta ({time_col})')

    # Histogram of time delta by cluster
    for cluster in range(optimal_clusters):
        cluster_data = df[df['cluster'] == cluster][time_col]
        axs[1].hist(
            cluster_data,
            bins=30,
            alpha=0.6,
            label=f'Cluster {cluster}'
        )

    axs[1].set_title('Histogram of Time Delta by Cluster')
    axs[1].set_xlabel(f'Time Delta ({time_col})')
    axs[1].set_ylabel('Frequency')
    axs[1].legend()

    plt.suptitle('Enhanced Cluster Visualization', fontsize=16)
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'kmeans_enhanced_viz.png'))
    logger.info(f"Saved enhanced visualizations to {output_dir}/kmeans_enhanced_viz.png")

    # If label column exists, analyze cluster composition
    if 'label' in df.columns:
        logger.info("Analyzing cluster composition by label...")

        # Create a crosstab of clusters vs labels
        cluster_label_counts = pd.crosstab(
            df['cluster'],
            df['label'],
            rownames=['Cluster'],
            colnames=['Label (0=Normal, 1=Attack)']
        )

        # Calculate percentages for better interpretation
        cluster_label_pct = cluster_label_counts.div(
            cluster_label_counts.sum(axis=1), axis=0
        ) * 100

        # Print cluster composition statistics
        logger.info("\nCluster composition by label (count):")
        logger.info(cluster_label_counts)

        logger.info("\nCluster composition by label (percentage):")
        logger.info(cluster_label_pct)

        # Save cluster composition statistics
        cluster_label_counts.to_csv(os.path.join(output_dir, 'cluster_label_counts.csv'))
        cluster_label_pct.to_csv(os.path.join(output_dir, 'cluster_label_percentages.csv'))

        # Visualization of cluster composition
        plt.figure(figsize=(10, 6))
        cluster_label_pct.plot(kind='bar', stacked=True)
        plt.title('Cluster Composition by Traffic Type')
        plt.xlabel('Cluster')
        plt.ylabel('Percentage')
        plt.legend(title='Traffic Type (0=Normal, 1=Attack)')
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, 'cluster_composition.png'))

        # Calculate attack likelihood for each cluster
        # This helps map clusters to attack probability
        attack_likelihood = {}
        for cluster in range(optimal_clusters):
            if 1 in cluster_label_pct.columns:  # If attack label exists
                attack_pct = cluster_label_pct.loc[cluster, 1] if 1 in cluster_label_pct.loc[cluster] else 0
                attack_likelihood[cluster] = attack_pct / 100.0
            else:
                attack_likelihood[cluster] = 0

        # Save attack likelihood mapping
        with open(os.path.join(output_dir, 'cluster_attack_likelihood.txt'), 'w') as f:
            f.write("Cluster Attack Likelihood (probability of being attack traffic):\n")
            for cluster, likelihood in attack_likelihood.items():
                f.write(f"Cluster {cluster}: {likelihood:.4f}\n")

        logger.info("\nCluster attack likelihood mapping saved")

    # Save the model and scaler for later use in the detector
    model_file = os.path.join(output_dir, 'kmeans_model.pkl')
    scaler_file = os.path.join(output_dir, 'kmeans_scaler.pkl')

    joblib.dump(bisect_kmeans, model_file)
    joblib.dump(scaler, scaler_file)

    logger.info(f"Saved trained model to {model_file}")
    logger.info(f"Saved feature scaler to {scaler_file}")

    return bisect_kmeans


def analyze_kmeans_predictions(
    model: BisectingKMeans,
    scaler: StandardScaler,
    feature_file: str,
    time_col: str = 'avg_time_delta',
    output_dir: str = 'models'
) -> None:
    """
    Analyze model predictions and assess detection capability.

    Args:
        model: Trained BisectingKMeans model
        scaler: Fitted StandardScaler
        feature_file: Path to feature file for analysis
        time_col: Column name for time delta
        output_dir: Directory to save analysis results
    """
    logger.info(f"Analyzing model predictions on {feature_file}...")

    # Load the features
    df = pd.read_csv(feature_file)

    if 'label' not in df.columns:
        logger.warning("No 'label' column found - cannot evaluate detection performance")
        return

    # Extract relevant feature and scale it
    X = df[[time_col]]
    X_scaled = scaler.transform(X)

    # Get cluster predictions
    df['predicted_cluster'] = model.predict(X_scaled)

    # Analyze detection performance
    attack_samples = df[df['label'] == 1]
    normal_samples = df[df['label'] == 0]

    # Check distribution of attack samples across clusters
    attack_cluster_counts = attack_samples['predicted_cluster'].value_counts()

    logger.info("\nAttack sample distribution across clusters:")
    for cluster, count in attack_cluster_counts.items():
        percentage = (count / len(attack_samples)) * 100
        logger.info(f"  Cluster {cluster}: {count} samples ({percentage:.2f}%)")

    # Check distribution of normal samples across clusters
    normal_cluster_counts = normal_samples['predicted_cluster'].value_counts()

    logger.info("\nNormal sample distribution across clusters:")
    for cluster, count in normal_cluster_counts.items():
        percentage = (count / len(normal_samples)) * 100
        logger.info(f"  Cluster {cluster}: {count} samples ({percentage:.2f}%)")

    # Save predictions
    df.to_csv(os.path.join(output_dir, 'kmeans_predictions.csv'), index=False)
    logger.info(f"Saved predictions to {output_dir}/kmeans_predictions.csv")


def main() -> None:
    """
    Main function to parse command line arguments and run the model training.
    """
    parser = argparse.ArgumentParser(description='Train K-means model for SYN flood detection')
    parser.add_argument('--features', type=str, default='data/processed/combined_features.csv',
                        help='Path to the feature CSV file')
    parser.add_argument('--output-dir', type=str, default='models',
                        help='Directory to save model and visualizations')
    parser.add_argument('--time-col', type=str, default='avg_time_delta',
                        help='Column name for time delta values')

    args = parser.parse_args()

    # Get absolute paths
    script_dir = os.path.dirname(os.path.abspath(__file__))
    features_path = os.path.join(script_dir, args.features)
    output_dir = os.path.join(script_dir, args.output_dir)

    # Train the model
    kmeans_model = train_kmeans_model(
        feature_file=features_path,
        output_dir=output_dir,
        time_col=args.time_col
    )

    if kmeans_model is not None:
        # Load the scaler
        scaler_path = os.path.join(output_dir, 'kmeans_scaler.pkl')
        scaler = joblib.load(scaler_path)

        # Analyze model predictions
        analyze_kmeans_predictions(
            model=kmeans_model,
            scaler=scaler,
            feature_file=features_path,
            time_col=args.time_col,
            output_dir=output_dir
        )

        logger.info("K-means model training and analysis complete!")
    else:
        logger.error("K-means model training failed!")


if __name__ == "__main__":
    main()
