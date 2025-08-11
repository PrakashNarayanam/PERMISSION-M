# Deploying to Render

This guide will help you deploy your Flask permission system to Render.

## Prerequisites

1. A Render account (free tier available)
2. Your code pushed to a Git repository (GitHub, GitLab, etc.)

## Step-by-Step Deployment

### Method 1: Using Render Dashboard (Recommended)

1. **Sign up/Login to Render**
   - Go to [render.com](https://render.com)
   - Sign up or login to your account

2. **Create a New Web Service**
   - Click "New +" button
   - Select "Web Service"
   - Connect your Git repository

3. **Configure the Service**
   - **Name**: `permission-system` (or any name you prefer)
   - **Environment**: `Python 3`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn app:app`

4. **Set Environment Variables**
   - Go to the "Environment" tab
   - Add the following environment variables:
     - `MONGO_URI`: Your MongoDB Atlas connection string
     - `SECRET_KEY`: A secure random string for Flask sessions

5. **Deploy**
   - Click "Create Web Service"
   - Render will automatically build and deploy your application

### Method 2: Using render.yaml (Blue/Green Deployment)

1. **Push your code with render.yaml**
   - The `render.yaml` file is already configured
   - Push your code to your Git repository

2. **Deploy via Render Dashboard**
   - Go to Render Dashboard
   - Click "New +" → "Blueprint"
   - Connect your repository
   - Render will use the `render.yaml` configuration

## Environment Variables Setup

In your Render dashboard, set these environment variables:

```
MONGO_URI=mongodb+srv://requests:lM32Oc0n3Z0Q68oR@cluster0.xvb7a3a.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0
SECRET_KEY=your-secure-secret-key-here
```

## Important Notes

1. **MongoDB Atlas**: Your application uses MongoDB Atlas. Make sure your cluster is accessible from Render's servers.

2. **Admin Credentials**: The default admin credentials are:
   - Username: `technoelite@nec`
   - Password: `technoelite@2025`
   - **Change these in production!**

3. **Custom Domain**: You can add a custom domain in the Render dashboard under "Settings" → "Custom Domains".

4. **SSL**: Render provides free SSL certificates automatically.

## Troubleshooting

### Common Issues:

1. **Build Failures**
   - Check that all dependencies are in `requirements.txt`
   - Ensure Python version is compatible

2. **Database Connection Issues**
   - Verify your MongoDB Atlas connection string
   - Check if your MongoDB cluster allows connections from Render's IP ranges

3. **Application Crashes**
   - Check the logs in Render dashboard
   - Ensure `gunicorn` is in requirements.txt
   - Verify the start command is correct

### Checking Logs:
- Go to your service in Render dashboard
- Click on "Logs" tab
- Check for any error messages

## Security Considerations

1. **Change Default Credentials**: Update the admin username and password in `app.py`
2. **Secure Secret Key**: Use a strong, random secret key
3. **Environment Variables**: Never commit sensitive data to your repository
4. **MongoDB Security**: Ensure your MongoDB Atlas cluster has proper security settings

## Monitoring

- Render provides basic monitoring in the dashboard
- Check the "Metrics" tab for performance data
- Set up alerts for downtime if needed

## Scaling

- Free tier: 1 instance
- Paid plans: Auto-scaling available
- Configure in the "Settings" tab

Your application will be available at: `https://your-app-name.onrender.com`

